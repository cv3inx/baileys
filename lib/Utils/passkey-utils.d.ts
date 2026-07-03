/** JSON shape of the server's WebAuthn PublicKeyCredentialRequestOptions */
export type PasskeyRequestOptions = {
    challenge: string;
    timeout: number;
    rpId: string;
    allowCredentials: Array<{
        id: string;
        type: string;
        transports?: string[];
    }>;
    userVerification: string;
    extensions?: {
        [k: string]: any;
    };
};
/** PublicKeyCredential.toJSON() shape — all binary fields base64url */
export type WebAuthnResponse = {
    id: string;
    rawId: string;
    type: string;
    response: {
        clientDataJSON: string;
        authenticatorData: string;
        signature: string;
        userHandle?: string | null;
    };
};
export function makePasskeyFlow({ query, authState, ev, logger, browser }: {
    query: (node: any, timeoutMs?: any) => Promise<any>;
    authState: any;
    ev: any;
    logger: any;
    browser: any;
}): {
    handlePasskeyRequestNotification: (node: any) => Promise<void>;
    handleContinuationNotification: (node: any) => Promise<void>;
    sendPasskeyResponse: (webAuthnResponse: WebAuthnResponse) => Promise<void>;
    sendPasskeyConfirmation: () => Promise<void>;
};
