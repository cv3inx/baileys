import { randomBytes } from 'crypto';
import { proto } from '../../WAProto/index.js';
import { getBinaryNodeChild, S_WHATSAPP_NET } from '../WABinary/index.js';
import { aesEncryptGCM, Curve, hkdf, hmacSign, sha256 } from './crypto.js';
import { bytesToCrockford } from './generics.js';
/**
 * WhatsApp "Shortcake" passkey companion-linking flow (CRSC).
 * Port of whatsmeow b572e5bc "pair: add support for passkeys".
 *
 * Server pushes <notification type="passkey_prologue_request"> after QR scan /
 * pair-code registration on passkey-locked accounts. The WebAuthn assertion
 * itself CANNOT be produced headlessly (rpId "whatsapp.com", server verifies
 * the signature against the account's registered passkey) — the consumer must
 * run navigator.credentials.get() in a real web.whatsapp.com context and feed
 * the assertion back via sendPasskeyResponse().
 *
 * Events emitted on `ev`:
 *  - 'pair-passkey.request'      { publicKey }  — WebAuthn PublicKeyCredentialRequestOptions (JSON)
 *  - 'pair-passkey.confirmation' { code, skipHandoffUX } — show code to user unless skipHandoffUX
 *  - 'pair-passkey.error'        { error, continuation }
 */
const HANDOFF_KEY_INFO = 'shortcake-passkey-handoff-v1';
const HANDOFF_KEY_TTL_MS = 5 * 60 * 1000;
const PAIRING_ENC_KEY_INFO = 'Pairing Information Encryption Key';
const nodeContentToBuffer = (content) => {
    if (typeof content === 'string') {
        return Buffer.from(content, 'utf-8');
    }
    if (content instanceof Uint8Array) {
        return Buffer.from(content);
    }
    return undefined;
};
export const makePasskeyFlow = ({ query, authState, ev, logger, browser }) => {
    /** { keyPair, nonce, ref, deviceType, encryptionKey } while a passkey pairing is in flight */
    let linkingCache = null;
    /** { hmac, ts } — proof key derived from the pre-rotation ADV secret */
    let handoffKey = null;
    let skipHandoffUX = false;
    const mdIq = (type, content) => ({
        tag: 'iq',
        attrs: { to: S_WHATSAPP_NET, type, xmlns: 'md' },
        content
    });
    const getPlatformType = () => {
        const platformType = (browser?.[1] || '').toUpperCase();
        return proto.DeviceProps.PlatformType[platformType] || proto.DeviceProps.PlatformType.CHROME;
    };
    const parsePasskeyRequestOptions = (node) => {
        const opts = getBinaryNodeChild(node, 'passkey_request_options');
        const content = nodeContentToBuffer(opts?.content);
        if (!content) {
            throw new Error('missing <passkey_request_options> in passkey notification');
        }
        return JSON.parse(content.toString('utf-8'));
    };
    /** `<iq type="get" xmlns="md"><passkey_request_options/></iq>` — fallback fetch */
    const getPasskeyRequestOptions = async () => {
        const resp = await query(mdIq('get', [{ tag: 'passkey_request_options', attrs: {} }]));
        return parsePasskeyRequestOptions(resp);
    };
    /** `<iq type="get" xmlns="md"><ref/></iq>` */
    const getCompanionRef = async () => {
        const resp = await query(mdIq('get', [{ tag: 'ref', attrs: {} }]));
        const ref = nodeContentToBuffer(getBinaryNodeChild(resp, 'ref')?.content);
        if (!ref) {
            throw new Error('missing <ref> in get ref response');
        }
        return ref.toString('utf-8');
    };
    /** handles <notification type="passkey_prologue_request"> */
    const handlePasskeyRequestNotification = async (node) => {
        if (node.attrs.from !== S_WHATSAPP_NET) {
            logger.warn({ from: node.attrs.from }, 'ignoring passkey notification from non-server JID');
            return;
        }
        let publicKey;
        try {
            publicKey = parsePasskeyRequestOptions(node);
        }
        catch (err) {
            logger.warn({ err: err?.message }, 'failed to parse passkey notification, fetching options');
            try {
                publicKey = await getPasskeyRequestOptions();
            }
            catch (secondErr) {
                ev.emit('pair-passkey.error', {
                    error: new Error(`failed to parse passkey notification: ${err?.message} (fetching also failed: ${secondErr?.message})`),
                    continuation: false
                });
                return;
            }
        }
        // handoff proof key must come from the PRE-rotation ADV secret
        handoffKey = {
            hmac: Buffer.from(hkdf(Buffer.from(authState.creds.advSecretKey, 'base64'), 32, { info: HANDOFF_KEY_INFO })),
            ts: Date.now()
        };
        authState.creds.advSecretKey = randomBytes(32).toString('base64');
        ev.emit('creds.update', { advSecretKey: authState.creds.advSecretKey });
        logger.info('received passkey prologue request, waiting for WebAuthn assertion');
        ev.emit('pair-passkey.request', { publicKey });
    };
    /**
     * Sends the externally-produced WebAuthn assertion to the server.
     * `webAuthnResponse` is the JSON-serializable PublicKeyCredential:
     * { id, rawId, type: 'public-key', response: { clientDataJSON, authenticatorData, signature, userHandle } }
     * with all binary fields base64url-encoded (i.e. credential.toJSON() shape).
     */
    const sendPasskeyResponse = async (webAuthnResponse) => {
        if (!webAuthnResponse?.rawId || !webAuthnResponse?.response) {
            throw new Error('invalid WebAuthn response: missing rawId/response');
        }
        const companionRef = await getCompanionRef();
        const keyPair = Curve.generateKeyPair();
        const nonce = randomBytes(32);
        const deviceType = getPlatformType();
        const ident = proto.CompanionEphemeralIdentity.encode({
            publicKey: keyPair.public,
            deviceType,
            ref: companionRef
        }).finish();
        const commitment = sha256(Buffer.concat([ident, nonce]));
        const prologuePayload = proto.ProloguePayload.encode({
            companionEphemeralIdentity: ident,
            commitment: { hash: commitment }
        }).finish();
        linkingCache = { keyPair, nonce, ref: companionRef, deviceType, encryptionKey: null };
        const prologueContent = [
            { tag: 'credential_id', attrs: {}, content: Buffer.from(webAuthnResponse.rawId, 'base64url') },
            { tag: 'webauthn_assertion', attrs: {}, content: Buffer.from(JSON.stringify(webAuthnResponse), 'utf-8') },
            { tag: 'prologue_payload', attrs: {}, content: prologuePayload }
        ];
        if (handoffKey && Date.now() - handoffKey.ts < HANDOFF_KEY_TTL_MS) {
            prologueContent.push({
                tag: 'pairing_handoff_proof',
                attrs: {},
                content: hmacSign(prologuePayload, handoffKey.hmac)
            });
            skipHandoffUX = true;
        }
        else {
            skipHandoffUX = false;
        }
        await query(mdIq('set', [{ tag: 'passkey_prologue', attrs: {}, content: prologueContent }]));
        handoffKey = null;
        logger.info('passkey prologue accepted, waiting for primary device');
    };
    /** handles <notification type="crsc_continuation"> — primary replied, derive keys + code */
    const handleContinuationNotification = async (node) => {
        if (node.attrs.from !== S_WHATSAPP_NET) {
            logger.warn({ from: node.attrs.from }, 'ignoring passkey continuation from non-server JID');
            return;
        }
        try {
            if (!linkingCache) {
                throw new Error('received passkey continuation without a pending pairing');
            }
            const identContent = nodeContentToBuffer(getBinaryNodeChild(node, 'primary_ephemeral_identity')?.content);
            if (!identContent) {
                throw new Error('missing <primary_ephemeral_identity> in continuation notification');
            }
            const primary = proto.PrimaryEphemeralIdentity.decode(identContent);
            if (primary.publicKey?.length !== 32 || primary.nonce?.length !== 32) {
                throw new Error('unexpected key/nonce length in primary ephemeral identity');
            }
            const sharedSecret = Curve.sharedKey(linkingCache.keyPair.private, Buffer.from(primary.publicKey));
            await query(mdIq('set', [{ tag: 'companion_nonce', attrs: {}, content: linkingCache.nonce }]));
            const salt = `Companion Pairing ${linkingCache.deviceType} with ref ${linkingCache.ref}`;
            linkingCache.encryptionKey = Buffer.from(hkdf(sharedSecret, 32, { salt: Buffer.from(salt), info: PAIRING_ENC_KEY_INFO }));
            const digest = sha256(Buffer.concat([linkingCache.nonce, Buffer.from(primary.publicKey)]));
            const codeBytes = Buffer.alloc(5);
            for (let i = 0; i < codeBytes.length; i++) {
                codeBytes[i] = primary.nonce[i] ^ digest[i];
            }
            const encoded = bytesToCrockford(codeBytes);
            const code = `${encoded.slice(0, 4)}-${encoded.slice(4)}`;
            ev.emit('pair-passkey.confirmation', { code, skipHandoffUX });
            if (skipHandoffUX) {
                logger.debug('sending automatic passkey confirmation');
                await sendPasskeyConfirmation();
            }
        }
        catch (error) {
            logger.warn({ err: error?.message }, 'failed to handle passkey continuation notification');
            ev.emit('pair-passkey.error', { error, continuation: true });
        }
    };
    /**
     * Confirms the code-match (call after the user verified the code from
     * 'pair-passkey.confirmation'; automatic when skipHandoffUX was true).
     */
    const sendPasskeyConfirmation = async () => {
        if (!linkingCache) {
            throw new Error('no passkey linking in progress');
        }
        if (!linkingCache.encryptionKey) {
            throw new Error('passkey linking has no encryption key yet');
        }
        const req = proto.PairingRequest.encode({
            companionPublicKey: authState.creds.noiseKey.public,
            companionIdentityKey: authState.creds.signedIdentityKey.public,
            advSecret: Buffer.from(authState.creds.advSecretKey, 'base64')
        }).finish();
        const iv = randomBytes(12);
        const encrypted = aesEncryptGCM(req, linkingCache.encryptionKey, iv, Buffer.alloc(0));
        const wrapped = proto.EncryptedPairingRequest.encode({
            encryptedPayload: encrypted,
            iv
        }).finish();
        await query(mdIq('set', [{ tag: 'encrypted_pairing_request', attrs: {}, content: wrapped }]));
        linkingCache = null;
        logger.info('passkey pairing confirmation sent');
    };
    return {
        handlePasskeyRequestNotification,
        handleContinuationNotification,
        sendPasskeyResponse,
        sendPasskeyConfirmation
    };
};
