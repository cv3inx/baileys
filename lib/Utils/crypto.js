import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'crypto';
import * as curve from 'libsignal/src/curve.js';
import { calculateSignature as rustSign, verifySignature as rustVerify } from 'whatsapp-rust-bridge';
import { KEY_BUNDLE_TYPE } from '../Defaults/index.js';
export { md5, hkdf } from 'whatsapp-rust-bridge';
// insure browser & node compatibility
const { subtle } = globalThis.crypto;
/** prefix version byte to the pub keys, required for some curve crypto functions */
export const generateSignalPubKey = (pubKey) => pubKey.length === 33 ? pubKey : Buffer.concat([KEY_BUNDLE_TYPE, pubKey]);
/**
 * Self-test the native signing path before trusting it, once at load.
 *
 * These signatures gate device pairing and prekey upload: a backend that
 * silently produced malformed output would not fail loudly, it would get the
 * account rejected by WhatsApp. So we require the native code to (a) round-trip
 * against itself, (b) interoperate with libsignal in both directions, and
 * (c) actually reject a tampered signature. Any doubt and we keep pure JS.
 */
const [nativeSign, nativeVerify] = (() => {
    try {
        const kp = curve.generateKeyPair();
        const msg = Buffer.from('baileys-native-crypto-selftest');
        const nSig = Buffer.from(rustSign(kp.privKey, msg));
        const jSig = curve.calculateSignature(kp.privKey, msg);
        if (nSig.length !== 64) {
            return [null, null];
        }
        // native <-> native, and native <-> libsignal, must all verify
        if (rustVerify(kp.pubKey, msg, nSig) === false) {
            return [null, null];
        }
        if (rustVerify(kp.pubKey, msg, jSig) === false) {
            return [null, null];
        }
        curve.verifySignature(kp.pubKey, msg, nSig); // throws if invalid
        // and a corrupted signature must NOT verify
        const bad = Buffer.from(nSig);
        bad[0] ^= 1;
        let rejected = false;
        try {
            rejected = rustVerify(kp.pubKey, msg, bad) === false;
        }
        catch {
            rejected = true;
        }
        if (!rejected) {
            return [null, null];
        }
        return [rustSign, rustVerify];
    }
    catch {
        return [null, null];
    }
})();
/** True when the fast native XEdDSA path passed its self-test and is in use. */
export const isNativeCurveEnabled = () => Boolean(nativeSign && nativeVerify);
export const Curve = {
    generateKeyPair: () => {
        const { pubKey, privKey } = curve.generateKeyPair();
        return {
            private: Buffer.from(privKey),
            // remove version byte
            public: Buffer.from(pubKey.slice(1))
        };
    },
    // derive public key from a private key (strip version byte to match generateKeyPair)
    publicKeyFromPrivate: (privateKey) => Buffer.from(curve.getPublicFromPrivateKey(privateKey).slice(1)),
    sharedKey: (privateKey, publicKey) => {
        const shared = curve.calculateAgreement(generateSignalPubKey(publicKey), privateKey);
        return Buffer.from(shared);
    },
    /**
     * XEdDSA sign. Prefers the native bridge: libsignal's fallback is
     * `curve25519-js`, a pure-JS implementation costing ~8 ms per call, which
     * blocks the event loop and is shared by every socket in the process.
     * The native path is ~120x faster (~0.07 ms).
     */
    sign: (privateKey, buf) => {
        if (nativeSign) {
            try {
                return Buffer.from(nativeSign(privateKey, buf));
            }
            catch {
                // fall through to the JS implementation
            }
        }
        return curve.calculateSignature(privateKey, buf);
    },
    /**
     * Returns a boolean rather than throwing. Note the two backends disagree on
     * how they report failure: the native one returns false, libsignal throws.
     * Both shapes are normalised here.
     *
     * XEdDSA signatures use a randomised nonce, so the two backends produce
     * different bytes for the same input. That is spec-conformant and they
     * cross-verify each other's output (checked over 200 random key/message
     * pairs), so mixing them across a restart or fallback is safe.
     */
    verify: (pubKey, message, signature) => {
        const key = generateSignalPubKey(pubKey);
        if (nativeVerify) {
            try {
                return nativeVerify(key, message, signature) !== false;
            }
            catch {
                return false;
            }
        }
        try {
            curve.verifySignature(key, message, signature);
            return true;
        }
        catch (error) {
            return false;
        }
    }
};
export const signedKeyPair = (identityKeyPair, keyId) => {
    const preKey = Curve.generateKeyPair();
    const pubKey = generateSignalPubKey(preKey.public);
    const signature = Curve.sign(identityKeyPair.private, pubKey);
    return { keyPair: preKey, signature, keyId };
};
const GCM_TAG_LENGTH = 128 >> 3;
/**
 * encrypt AES 256 GCM;
 * where the tag tag is suffixed to the ciphertext
 * */
export function aesEncryptGCM(plaintext, key, iv, additionalData) {
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(additionalData);
    return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}
/**
 * decrypt AES 256 GCM;
 * where the auth tag is suffixed to the ciphertext
 * */
export function aesDecryptGCM(ciphertext, key, iv, additionalData) {
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    // decrypt additional adata
    const enc = ciphertext.slice(0, ciphertext.length - GCM_TAG_LENGTH);
    const tag = ciphertext.slice(ciphertext.length - GCM_TAG_LENGTH);
    // set additional data
    decipher.setAAD(additionalData);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(enc), decipher.final()]);
}
export function aesEncryptCTR(plaintext, key, iv) {
    const cipher = createCipheriv('aes-256-ctr', key, iv);
    return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}
export function aesDecryptCTR(ciphertext, key, iv) {
    const decipher = createDecipheriv('aes-256-ctr', key, iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
/** decrypt AES 256 CBC; where the IV is prefixed to the buffer */
export function aesDecrypt(buffer, key) {
    return aesDecryptWithIV(buffer.subarray(16), key, buffer.subarray(0, 16));
}
/** decrypt AES 256 CBC */
export function aesDecryptWithIV(buffer, key, IV) {
    const aes = createDecipheriv('aes-256-cbc', key, IV);
    return Buffer.concat([aes.update(buffer), aes.final()]);
}
// encrypt AES 256 CBC; where a random IV is prefixed to the buffer
export function aesEncrypt(buffer, key) {
    const IV = randomBytes(16);
    const aes = createCipheriv('aes-256-cbc', key, IV);
    return Buffer.concat([IV, aes.update(buffer), aes.final()]); // prefix IV to the buffer
}
// encrypt AES 256 CBC with a given IV
export function aesEncrypWithIV(buffer, key, IV) {
    const aes = createCipheriv('aes-256-cbc', key, IV);
    return Buffer.concat([aes.update(buffer), aes.final()]); // prefix IV to the buffer
}
// coerce serialized Buffer-likes back to Buffer. Covers:
//   - real Buffer / typed array / string / null  -> passthrough
//   - {type:'Buffer', data:[...]}                -> Buffer (Node toJSON shape)
//   - plain array [...]                          -> Buffer
//   - {data:[...] | Uint8Array}                  -> Buffer (loose wrapper)
//   - {"0":1,"1":2,...} numeric-keyed object     -> Buffer (JSON.stringify of a
//                                                   Uint8Array revives like this)
function toBuf(v) {
    if (v == null || Buffer.isBuffer(v) || typeof v === 'string' || ArrayBuffer.isView(v)) {
        return v;
    }
    if (Array.isArray(v)) {
        return Buffer.from(v);
    }
    if (typeof v === 'object') {
        if (v.type === 'Buffer' && (Array.isArray(v.data) || v.data instanceof Uint8Array)) {
            return Buffer.from(v.data);
        }
        if (Array.isArray(v.data) || v.data instanceof Uint8Array) {
            return Buffer.from(v.data);
        }
        // JSON.stringify(Uint8Array) -> {"0":n,"1":n,...}; rebuild from numeric keys
        const keys = Object.keys(v);
        if (keys.length && keys.every(k => /^\d+$/.test(k))) {
            const arr = new Uint8Array(keys.length);
            for (let i = 0; i < keys.length; i++) {
                arr[i] = v[i];
            }
            return Buffer.from(arr);
        }
    }
    return v;
}
// sign HMAC using SHA 256
export function hmacSign(buffer, key, variant = 'sha256') {
    return createHmac(variant, toBuf(key)).update(toBuf(buffer)).digest();
}
export function sha256(buffer) {
    return createHash('sha256').update(buffer).digest();
}
export async function derivePairingCodeKey(pairingCode, salt) {
    // Convert inputs to formats Web Crypto API can work with
    const encoder = new TextEncoder();
    const pairingCodeBuffer = encoder.encode(pairingCode);
    const saltBuffer = new Uint8Array(salt instanceof Uint8Array ? salt : new Uint8Array(salt));
    // Import the pairing code as key material
    const keyMaterial = await subtle.importKey('raw', pairingCodeBuffer, { name: 'PBKDF2' }, false, [
        'deriveBits'
    ]);
    // Derive bits using PBKDF2 with the same parameters
    // 2 << 16 = 131,072 iterations
    const derivedBits = await subtle.deriveBits({
        name: 'PBKDF2',
        salt: saltBuffer,
        iterations: 2 << 16,
        hash: 'SHA-256'
    }, keyMaterial, 32 * 8 // 32 bytes * 8 = 256 bits
    );
    return Buffer.from(derivedBits);
}
//# sourceMappingURL=crypto.js.map