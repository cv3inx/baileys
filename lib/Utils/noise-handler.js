import { Boom } from '@hapi/boom';
import { proto } from '../../WAProto/index.js';
import { NOISE_MODE, WA_CERT_DETAILS } from '../Defaults/index.js';
import { decodeBinaryNode } from '../WABinary/index.js';
import { aesDecryptGCM, aesEncryptGCM, Curve, hkdf, sha256 } from './crypto.js';
const IV_LENGTH = 12;
const EMPTY_BUFFER = Buffer.alloc(0);
/** Starting size of each socket's receive buffer. Most WA frames are well under this. */
const INITIAL_RECV_BUFFER = 8 * 1024;
/** Shrink back to INITIAL_RECV_BUFFER once drained if a big frame grew us past this. */
const MAX_IDLE_RECV_BUFFER = 256 * 1024;
const generateIV = (counter) => {
    const iv = new ArrayBuffer(IV_LENGTH);
    new DataView(iv).setUint32(8, counter);
    return new Uint8Array(iv);
};
class TransportState {
    constructor(encKey, decKey) {
        this.encKey = encKey;
        this.decKey = decKey;
        this.readCounter = 0;
        this.writeCounter = 0;
        this.iv = new Uint8Array(IV_LENGTH);
    }
    encrypt(plaintext) {
        const c = this.writeCounter++;
        this.iv[8] = (c >>> 24) & 0xff;
        this.iv[9] = (c >>> 16) & 0xff;
        this.iv[10] = (c >>> 8) & 0xff;
        this.iv[11] = c & 0xff;
        return aesEncryptGCM(plaintext, this.encKey, this.iv, EMPTY_BUFFER);
    }
    decrypt(ciphertext) {
        const c = this.readCounter++;
        this.iv[8] = (c >>> 24) & 0xff;
        this.iv[9] = (c >>> 16) & 0xff;
        this.iv[10] = (c >>> 8) & 0xff;
        this.iv[11] = c & 0xff;
        return aesDecryptGCM(ciphertext, this.decKey, this.iv, EMPTY_BUFFER);
    }
}
export const makeNoiseHandler = ({ keyPair: { private: privateKey, public: publicKey }, NOISE_HEADER, logger, routingInfo }) => {
    logger = logger.child({ class: 'ns' });
    const data = Buffer.from(NOISE_MODE);
    let hash = data.byteLength === 32 ? data : sha256(data);
    let salt = hash;
    let encKey = hash;
    let decKey = hash;
    let counter = 0;
    let sentIntro = false;
    // Growable receive buffer with read/write cursors.
    //
    // This used to be `inBytes = Buffer.concat([inBytes, newData])` on every
    // socket 'data' event, which reallocates and copies the whole backlog per
    // chunk — quadratic in chunks (measured ~250 ms for 2000 x 512 B). With
    // thousands of sockets sharing one event loop that copying dominates.
    // Now appends are amortised O(1) and the buffer is compacted in place.
    let inBytes = Buffer.allocUnsafe(INITIAL_RECV_BUFFER);
    let readPos = 0;
    let writePos = 0;
    /** Reclaims consumed space; grows (doubling) only when genuinely needed. */
    const ensureCapacity = (extra) => {
        if (writePos + extra <= inBytes.length) {
            return;
        }
        const pending = writePos - readPos;
        // Sliding the live bytes down is enough whenever they now fit.
        if (readPos > 0 && pending + extra <= inBytes.length) {
            inBytes.copy(inBytes, 0, readPos, writePos);
            readPos = 0;
            writePos = pending;
            return;
        }
        let cap = inBytes.length || INITIAL_RECV_BUFFER;
        while (cap < pending + extra) {
            cap *= 2;
        }
        const next = Buffer.allocUnsafe(cap);
        inBytes.copy(next, 0, readPos, writePos);
        inBytes = next;
        readPos = 0;
        writePos = pending;
    };
    const append = (chunk) => {
        ensureCapacity(chunk.length);
        // chunk may be a Uint8Array from ws; Buffer.prototype.set handles both.
        inBytes.set(chunk, writePos);
        writePos += chunk.length;
    };
    /**
     * Called once a read pass drains what it can. Resets cursors when empty and
     * releases an oversized buffer so one large frame doesn't pin memory per
     * socket for the process lifetime.
     */
    const compact = () => {
        if (readPos === writePos) {
            readPos = writePos = 0;
            if (inBytes.length > MAX_IDLE_RECV_BUFFER) {
                inBytes = Buffer.allocUnsafe(INITIAL_RECV_BUFFER);
            }
        }
    };
    let transport = null;
    let isWaitingForTransport = false;
    let pendingOnFrame = null;
    let introHeader;
    if (routingInfo) {
        introHeader = Buffer.alloc(7 + routingInfo.byteLength + NOISE_HEADER.length);
        introHeader.write('ED', 0, 'utf8');
        introHeader.writeUint8(0, 2);
        introHeader.writeUint8(1, 3);
        introHeader.writeUint8(routingInfo.byteLength >> 16, 4);
        introHeader.writeUint16BE(routingInfo.byteLength & 65535, 5);
        introHeader.set(routingInfo, 7);
        introHeader.set(NOISE_HEADER, 7 + routingInfo.byteLength);
    }
    else {
        introHeader = Buffer.from(NOISE_HEADER);
    }
    const authenticate = (data) => {
        if (!transport) {
            hash = sha256(Buffer.concat([hash, data]));
        }
    };
    const encrypt = (plaintext) => {
        if (transport) {
            return transport.encrypt(plaintext);
        }
        const result = aesEncryptGCM(plaintext, encKey, generateIV(counter++), hash);
        authenticate(result);
        return result;
    };
    const decrypt = (ciphertext) => {
        if (transport) {
            return transport.decrypt(ciphertext);
        }
        const result = aesDecryptGCM(ciphertext, decKey, generateIV(counter++), hash);
        authenticate(ciphertext);
        return result;
    };
    const localHKDF = (data) => {
        const key = hkdf(Buffer.from(data), 64, { salt, info: '' });
        return [key.subarray(0, 32), key.subarray(32)];
    };
    const mixIntoKey = (data) => {
        const [write, read] = localHKDF(data);
        salt = write;
        encKey = read;
        decKey = read;
        counter = 0;
    };
    const finishInit = async () => {
        isWaitingForTransport = true;
        const [write, read] = localHKDF(new Uint8Array(0));
        transport = new TransportState(write, read);
        isWaitingForTransport = false;
        logger.trace('Noise handler transitioned to Transport state');
        if (pendingOnFrame) {
            logger.trace({ length: writePos - readPos }, 'Flushing buffered frames after transport ready');
            await processData(pendingOnFrame);
            pendingOnFrame = null;
        }
    };
    const processData = async (onFrame) => {
        let size;
        while (true) {
            const avail = writePos - readPos;
            if (avail < 3)
                return compact();
            size = (inBytes[readPos] << 16) | (inBytes[readPos + 1] << 8) | inBytes[readPos + 2];
            if (avail < size + 3)
                return compact();
            const start = readPos + 3;
            let frame = inBytes.subarray(start, start + size);
            readPos = start + size;
            if (transport) {
                // decrypt allocates a fresh buffer, so the view above cannot be
                // invalidated by a later append/compact while we await below.
                const result = transport.decrypt(frame);
                frame = await decodeBinaryNode(result);
            }
            else {
                // Handshake path hands the raw view to the caller. Copy it: the
                // caller may hold it across a yield, after which compact() could
                // shift these bytes out from under it.
                frame = Buffer.from(frame);
            }
            if (logger.level === 'trace') {
                logger.trace({ msg: frame?.attrs?.id }, 'recv frame');
            }
            onFrame(frame);
        }
    };
    authenticate(NOISE_HEADER);
    authenticate(publicKey);
    return {
        encrypt,
        decrypt,
        authenticate,
        mixIntoKey,
        finishInit,
        processHandshake: ({ serverHello }, noiseKey) => {
            authenticate(serverHello.ephemeral);
            mixIntoKey(Curve.sharedKey(privateKey, serverHello.ephemeral));
            const decStaticContent = decrypt(serverHello.static);
            mixIntoKey(Curve.sharedKey(privateKey, decStaticContent));
            const certDecoded = decrypt(serverHello.payload);
            const { intermediate: certIntermediate, leaf } = proto.CertChain.decode(certDecoded);
            // leaf
            if (!leaf?.details || !leaf?.signature) {
                throw new Boom('invalid noise leaf certificate', { statusCode: 400 });
            }
            if (!certIntermediate?.details || !certIntermediate?.signature) {
                throw new Boom('invalid noise intermediate certificate', { statusCode: 400 });
            }
            const details = proto.CertChain.NoiseCertificate.Details.decode(certIntermediate.details);
            const { issuerSerial } = details;
            const verify = Curve.verify(details.key, leaf.details, leaf.signature);
            const verifyIntermediate = Curve.verify(WA_CERT_DETAILS.PUBLIC_KEY, certIntermediate.details, certIntermediate.signature);
            if (!verify) {
                throw new Boom('noise certificate signature invalid', { statusCode: 400 });
            }
            if (!verifyIntermediate) {
                throw new Boom('noise intermediate certificate signature invalid', { statusCode: 400 });
            }
            if (issuerSerial !== WA_CERT_DETAILS.SERIAL) {
                throw new Boom('certification match failed', { statusCode: 400 });
            }
            const keyEnc = encrypt(noiseKey.public);
            mixIntoKey(Curve.sharedKey(noiseKey.private, serverHello.ephemeral));
            return keyEnc;
        },
        encodeFrame: (data) => {
            if (transport) {
                data = transport.encrypt(data);
            }
            const dataLen = data.byteLength;
            const introSize = sentIntro ? 0 : introHeader.length;
            const frame = Buffer.allocUnsafe(introSize + 3 + dataLen);
            if (!sentIntro) {
                frame.set(introHeader);
                sentIntro = true;
            }
            frame[introSize] = (dataLen >>> 16) & 0xff;
            frame[introSize + 1] = (dataLen >>> 8) & 0xff;
            frame[introSize + 2] = dataLen & 0xff;
            frame.set(data, introSize + 3);
            return frame;
        },
        decodeFrame: async (newData, onFrame) => {
            append(newData);
            if (isWaitingForTransport) {
                pendingOnFrame = onFrame;
                return;
            }
            await processData(onFrame);
        }
    };
};
//# sourceMappingURL=noise-handler.js.map