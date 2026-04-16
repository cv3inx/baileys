import { createHmac } from 'crypto';
/**
 * Compute a cstoken (NCT fallback) via HMAC-SHA256(nctSalt, recipientLid).
 * Used when no tctoken is available for a 1:1 message.
 */
export function computeCsToken(nctSalt, recipientLid) {
    const hmac = createHmac('sha256', Buffer.from(nctSalt));
    hmac.update(recipientLid, 'utf8');
    return new Uint8Array(hmac.digest());
}
export async function buildTcTokenFromJid({ authState, jid, baseContent = [] }) {
    try {
        const tcTokenData = await authState.keys.get('tctoken', [jid]);
        const tcTokenBuffer = tcTokenData?.[jid]?.token;
        if (!tcTokenBuffer)
            return baseContent.length > 0 ? baseContent : undefined;
        baseContent.push({
            tag: 'tctoken',
            attrs: {},
            content: tcTokenBuffer
        });
        return baseContent;
    }
    catch (error) {
        return baseContent.length > 0 ? baseContent : undefined;
    }
}