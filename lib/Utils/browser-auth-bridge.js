import { chmod, mkdir, writeFile } from 'fs/promises';
import { join } from 'path';
import { jidDecode, jidEncode } from '../WABinary/index.js';
import { initAuthCreds } from './auth-utils.js';
import { Curve, generateSignalPubKey } from './crypto.js';
import { BufferJSON } from './generics.js';
/**
 * Browser-auth bridge — import an already-authenticated WhatsApp Web session into
 * Baileys auth state. Port of upstream PR #2676.
 *
 * Passkey-locked accounts can't be linked headlessly (the WebAuthn assertion needs a
 * real web.whatsapp.com context). This sidesteps that: the user logs into WhatsApp Web
 * ONCE in a browser (which clears the passkey), you extract that companion session, and
 * reuse it as Baileys creds. No fresh pairing, no passkey prompt on the Baileys side.
 *
 * Run `extractWhatsAppWebAuthFromBrowser()` inside the browser page context
 * (Puppeteer/Playwright `page.evaluate`, or paste into DevTools console), then feed the
 * resulting JSON to `makeBrowserAuthImport()` / `writeBrowserAuthToMultiFile()` in Node.
 *
 * Caveats (see upstream thread): the extracted creds ARE the browser's linked device —
 * close the WA Web tab (don't log out, that revokes it), one live connection per companion,
 * and this only clears Tier-1 (login-time passkey); Tier-2 Business accounts still 428.
 */
const bufferFromB64 = (value) => Buffer.from(value, 'base64');
const bufferJsonToBuffer = (value) => bufferFromB64(value.__b64);
const browserJidToBaileysJid = (jid) => {
    const decoded = jidDecode(jid);
    if (!decoded) {
        throw new Error(`Could not normalize browser JID: ${jid}`);
    }
    return jidEncode(decoded.user, decoded.server === 'c.us' ? 's.whatsapp.net' : decoded.server, decoded.device);
};
const fixFileName = (file) => file.replace(/\//g, '__').replace(/:/g, '-');
const jidUser = (jid) => {
    const decoded = jidDecode(jid);
    if (!decoded) {
        throw new Error(`Could not decode JID: ${jid}`);
    }
    return decoded.user;
};
const selectNoiseKeyPair = (noise) => {
    for (const privateCandidate of noise.privateKeyCandidates) {
        const privateKey = bufferFromB64(privateCandidate.value);
        const derivedPublicKey = Curve.publicKeyFromPrivate(privateKey);
        for (const publicCandidate of noise.publicKeyCandidates) {
            const publicKey = bufferFromB64(publicCandidate.value);
            if (derivedPublicKey.equals(publicKey)) {
                return {
                    keyPair: { private: privateKey, public: publicKey },
                    privateIvIndex: privateCandidate.ivIndex,
                    publicIvIndex: publicCandidate.ivIndex
                };
            }
        }
    }
    throw new Error('Could not match WhatsApp Web Noise private/public key candidates');
};
const selectRecoveryToken = (candidates, usedIvIndexes) => {
    if (!candidates?.length) {
        return undefined;
    }
    return candidates.find(candidate => !usedIvIndexes.has(candidate.ivIndex)) || candidates[0];
};
const toKeyPair = (keyPair) => ({
    private: bufferJsonToBuffer(keyPair.privKey),
    public: bufferJsonToBuffer(keyPair.pubKey)
});
const toSignedKeyPair = (signedPreKey, identityKey) => {
    const keyPair = toKeyPair(signedPreKey.keyPair);
    const signature = Curve.sign(identityKey.private, generateSignalPubKey(keyPair.public));
    return {
        keyPair,
        signature,
        keyId: signedPreKey.keyId
    };
};
export const makeBrowserAuthImport = (extract, options = {}) => {
    const selectedNoise = selectNoiseKeyPair(extract.noise);
    const recoveryToken = selectRecoveryToken(extract.noise.recoveryTokenCandidates, new Set([selectedNoise.privateIvIndex, selectedNoise.publicIvIndex]));
    if (!recoveryToken) {
        throw new Error('WhatsApp Web auth export did not include a recovery token');
    }
    const signedPreKey = extract.signal.lastSignedPreKeyId === undefined
        ? extract.signal.signedPreKeys[0]
        : extract.signal.signedPreKeys.find(key => key.keyId === extract.signal.lastSignedPreKeyId);
    if (!signedPreKey) {
        throw new Error('WhatsApp Web auth export did not include a signed pre-key');
    }
    const signedIdentityKey = {
        private: bufferFromB64(extract.signal.signedIdentityKey.private),
        public: bufferFromB64(extract.signal.signedIdentityKey.public)
    };
    const creds = initAuthCreds();
    Object.assign(creds, {
        noiseKey: selectedNoise.keyPair,
        signedIdentityKey,
        signedPreKey: toSignedKeyPair(signedPreKey, signedIdentityKey),
        registrationId: extract.signal.registrationId,
        advSecretKey: recoveryToken.value,
        processedHistoryMessages: [],
        nextPreKeyId: extract.signal.nextPreKeyId,
        firstUnuploadedPreKeyId: extract.signal.firstUnuploadedPreKeyId,
        accountSyncCounter: 0,
        accountSettings: { unarchiveChats: false },
        registered: false,
        account: {
            details: bufferJsonToBuffer(extract.signal.advSignedIdentity.details),
            accountSignatureKey: bufferJsonToBuffer(extract.signal.advSignedIdentity.accountSignatureKey),
            accountSignature: bufferJsonToBuffer(extract.signal.advSignedIdentity.accountSignature),
            deviceSignature: bufferJsonToBuffer(extract.signal.advSignedIdentity.deviceSignature)
        },
        me: {
            id: browserJidToBaileysJid(extract.localStorage.lastWidMd),
            lid: extract.localStorage.waLid,
            name: options.name
        },
        signalIdentities: [
            {
                identifier: { name: extract.localStorage.waLid, deviceId: 0 },
                identifierKey: generateSignalPubKey(signedIdentityKey.public)
            }
        ],
        platform: options.platform || 'web'
    });
    const preKeys = {};
    for (const preKey of extract.signal.preKeys) {
        preKeys[preKey.keyId] = toKeyPair(preKey.keyPair);
    }
    const pnUser = jidUser(browserJidToBaileysJid(extract.localStorage.lastWidMd));
    const lidUser = jidUser(extract.localStorage.waLid);
    return {
        creds,
        keys: {
            'pre-key': preKeys,
            'lid-mapping': {
                [pnUser]: lidUser,
                [`${lidUser}_reverse`]: pnUser
            }
        },
        selectedNoiseCandidate: {
            privateIvIndex: selectedNoise.privateIvIndex,
            publicIvIndex: selectedNoise.publicIvIndex,
            recoveryTokenIvIndex: recoveryToken?.ivIndex
        }
    };
};
export const writeBrowserAuthToMultiFile = async (folder, extract, options = {}) => {
    const authImport = makeBrowserAuthImport(extract, options);
    await mkdir(folder, { recursive: true, mode: 0o700 });
    await chmod(folder, 0o700);
    const writePrivateJson = async (file, value) => {
        const filePath = join(folder, file);
        await writeFile(filePath, JSON.stringify(value, BufferJSON.replacer), { mode: 0o600 });
        await chmod(filePath, 0o600);
    };
    await writePrivateJson('creds.json', authImport.creds);
    for (const category in authImport.keys) {
        const values = authImport.keys[category];
        for (const id in values) {
            const value = values[id];
            if (value) {
                await writePrivateJson(fixFileName(`${category}-${id}.json`), value);
            }
        }
    }
    return authImport;
};
/**
 * Run this INSIDE the browser page context (page.evaluate / DevTools console) of a
 * logged-in web.whatsapp.com tab. Reads localStorage + IndexedDB, decrypts the noise
 * and signal keys via crypto.subtle, and returns a BrowserAuthExtract JSON. Sends nothing
 * over the network (web.whatsapp.com CSP blocks that anyway).
 */
export const extractWhatsAppWebAuthFromBrowser = async () => {
    const b64ToBytes = (value) => Uint8Array.from(atob(value), char => char.charCodeAt(0));
    const bytesToB64 = (value) => {
        const bytes = value instanceof ArrayBuffer
            ? new Uint8Array(value)
            : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        let binary = '';
        for (let i = 0; i < bytes.length; i += 0x8000) {
            binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
        }
        return btoa(binary);
    };
    const request = (req) => new Promise((resolve, reject) => {
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
    });
    const openDb = (name) => new Promise((resolve, reject) => {
        const req = indexedDB.open(name);
        req.onupgradeneeded = () => {
            req.transaction?.abort();
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error || new Error(`IndexedDB database not found: ${name}`));
    });
    const get = async (dbName, storeName, key) => {
        const db = await openDb(dbName);
        try {
            return await request(db.transaction(storeName, 'readonly').objectStore(storeName).get(key));
        }
        finally {
            db.close();
        }
    };
    const getAll = async (dbName, storeName) => {
        const db = await openDb(dbName);
        try {
            return await request(db.transaction(storeName, 'readonly').objectStore(storeName).getAll());
        }
        finally {
            db.close();
        }
    };
    const localStorageJson = (key) => {
        const value = localStorage.getItem(key);
        if (value === null) {
            throw new Error(`WhatsApp Web localStorage is missing ${key}`);
        }
        return JSON.parse(value);
    };
    const requireString = (value, label) => {
        if (typeof value !== 'string' || !value.length) {
            throw new Error(`WhatsApp Web auth export did not include ${label}`);
        }
        return value;
    };
    const requireArray = (value, label) => {
        if (!Array.isArray(value)) {
            throw new Error(`WhatsApp Web auth export did not include ${label}`);
        }
        return value;
    };
    const requireNonEmptyArray = (value, label) => {
        const values = requireArray(value, label);
        if (!values.length) {
            throw new Error(`WhatsApp Web auth export did not include ${label}`);
        }
        return values;
    };
    const requireRecord = (value, label) => {
        if (!value || typeof value !== 'object' || Array.isArray(value)) {
            throw new Error(`WhatsApp Web auth export did not include ${label}`);
        }
        return value;
    };
    const requireSafeInteger = (value, label) => {
        const number = Number(value);
        if (!Number.isSafeInteger(number)) {
            throw new Error(`WhatsApp Web auth export did not include a valid ${label}`);
        }
        return number;
    };
    const requireEncryptedStaticKey = (value, label) => {
        const record = requireRecord(value, label);
        if (!(record.value instanceof ArrayBuffer) && !ArrayBuffer.isView(record.value)) {
            throw new Error(`WhatsApp Web auth export did not include ${label} ciphertext`);
        }
        if (!(record.encKey instanceof CryptoKey)) {
            throw new Error(`WhatsApp Web auth export did not include ${label} decryption key`);
        }
        return record;
    };
    const requireBufferJson = (value, label) => {
        const record = requireRecord(value, label);
        if (typeof record.__b64 !== 'string' || !record.__b64.length) {
            throw new Error(`WhatsApp Web auth export did not include ${label}`);
        }
        return record;
    };
    const lastWidMd = requireString(localStorageJson('last-wid-md'), 'last-wid-md');
    const waLid = requireString(localStorageJson('WALid'), 'WALid');
    const salt = b64ToBytes(requireString(localStorageJson('WAWebEncKeySalt'), 'WAWebEncKeySalt'));
    const noiseIvs = requireNonEmptyArray(localStorageJson('WANoiseInfoIv'), 'WANoiseInfoIv').map((iv, index) => requireString(iv, `WANoiseInfoIv[${index}]`));
    const encryptedNoise = requireRecord(localStorageJson('WANoiseInfo'), 'WANoiseInfo');
    for (const field of ['privKey', 'pubKey', 'recoveryToken']) {
        requireString(encryptedNoise[field], `WANoiseInfo.${field}`);
    }
    const encryptedKeyRecord = await get('wawc_db_enc', 'keys', 1);
    if (!(encryptedKeyRecord?.key instanceof CryptoKey)) {
        throw new Error('WhatsApp Web auth export did not include the encrypted storage key');
    }
    const noiseAesKey = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: new Uint8Array([0]) }, encryptedKeyRecord.key, { name: 'AES-CBC', length: 128 }, false, ['decrypt']);
    const decryptNoiseCandidates = async (field) => {
        const encryptedValue = encryptedNoise[field];
        if (!encryptedValue) {
            return [];
        }
        const candidates = [];
        await Promise.all(noiseIvs.map(async (iv, ivIndex) => {
            try {
                const value = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: b64ToBytes(iv) }, noiseAesKey, b64ToBytes(encryptedValue));
                candidates.push({ ivIndex, value: bytesToB64(value) });
            }
            catch { }
        }));
        return candidates.sort((left, right) => left.ivIndex - right.ivIndex);
    };
    const requireCandidates = async (field) => {
        const candidates = await decryptNoiseCandidates(field);
        if (!candidates.length) {
            throw new Error(`WhatsApp Web auth export did not include decryptable WANoiseInfo.${field}`);
        }
        return candidates;
    };
    const privateKeyCandidates = await requireCandidates('privKey');
    const publicKeyCandidates = await requireCandidates('pubKey');
    const recoveryTokenCandidates = await requireCandidates('recoveryToken');
    const certificateChainBufferCandidates = await decryptNoiseCandidates('certificateChainBuffer');
    const signalMetaRows = requireNonEmptyArray(await getAll('signal-storage', 'signal-meta-store'), 'signal meta records');
    const signalMeta = Object.fromEntries(signalMetaRows.map(row => [row.key, row.value]));
    const decryptStaticKey = async (record) => bytesToB64(await crypto.subtle.decrypt({ name: 'AES-CTR', counter: new Uint8Array(16), length: 64 }, record.encKey, record.value));
    const mapBuffer = (value) => {
        if (value === null || value === undefined) {
            return value;
        }
        if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
            return { __b64: bytesToB64(value) };
        }
        if (Array.isArray(value)) {
            return value.map(mapBuffer);
        }
        if (typeof value === 'object') {
            return Object.fromEntries(Object.entries(value)
                .filter(([, child]) => !(child instanceof CryptoKey))
                .map(([key, child]) => [key, mapBuffer(child)]));
        }
        return value;
    };
    const advSignedIdentity = requireRecord(mapBuffer(signalMeta.adv_signed_identity), 'adv signed identity');
    const preKeys = requireNonEmptyArray((await getAll('signal-storage', 'prekey-store')).map(mapBuffer), 'pre-key records');
    const signedPreKeys = requireNonEmptyArray((await getAll('signal-storage', 'signed-prekey-store')).map(mapBuffer), 'signed pre-key records');
    const lastSignedPreKeyId = signalMeta.signal_last_spk_id === undefined
        ? undefined
        : requireSafeInteger(signalMeta.signal_last_spk_id, 'last signed pre-key id');
    return {
        localStorage: { lastWidMd, waLid },
        noise: { privateKeyCandidates, publicKeyCandidates, recoveryTokenCandidates, certificateChainBufferCandidates },
        signal: {
            registrationId: requireSafeInteger(signalMeta.signal_reg_id, 'registration id'),
            nextPreKeyId: requireSafeInteger(signalMeta.signal_next_pk_id, 'next pre-key id'),
            firstUnuploadedPreKeyId: requireSafeInteger(signalMeta.signal_first_unupload_pk_id, 'first unuploaded pre-key id'),
            lastSignedPreKeyId,
            signedIdentityKey: {
                private: await decryptStaticKey(requireEncryptedStaticKey(signalMeta.signal_static_privkey, 'static private key')),
                public: await decryptStaticKey(requireEncryptedStaticKey(signalMeta.signal_static_pubkey, 'static public key'))
            },
            advSignedIdentity: {
                details: requireBufferJson(advSignedIdentity.details, 'adv signed identity details'),
                accountSignatureKey: requireBufferJson(advSignedIdentity.accountSignatureKey, 'adv signed identity account signature key'),
                accountSignature: requireBufferJson(advSignedIdentity.accountSignature, 'adv signed identity account signature'),
                deviceSignature: requireBufferJson(advSignedIdentity.deviceSignature, 'adv signed identity device signature')
            },
            preKeys,
            signedPreKeys
        }
    };
};
