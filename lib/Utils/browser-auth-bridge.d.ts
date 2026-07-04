import type { AuthenticationCreds, SignalDataSet } from '../Types/index.js';
export type BrowserAuthNoiseCandidate = {
    ivIndex: number;
    value: string;
};
export type BrowserAuthBufferJson = {
    __b64: string;
};
export type BrowserAuthKeyPair = {
    keyId: number;
    keyPair: {
        privKey: BrowserAuthBufferJson;
        pubKey: BrowserAuthBufferJson;
    };
    signature?: BrowserAuthBufferJson;
};
export type BrowserAuthPreKey = {
    keyId: number;
    keyPair: {
        privKey: BrowserAuthBufferJson;
        pubKey: BrowserAuthBufferJson;
    };
};
export type BrowserAuthExtract = {
    localStorage: {
        lastWidMd: string;
        waLid: string;
    };
    noise: {
        privateKeyCandidates: BrowserAuthNoiseCandidate[];
        publicKeyCandidates: BrowserAuthNoiseCandidate[];
        recoveryTokenCandidates?: BrowserAuthNoiseCandidate[];
        certificateChainBufferCandidates?: BrowserAuthNoiseCandidate[];
    };
    signal: {
        registrationId: number;
        nextPreKeyId: number;
        firstUnuploadedPreKeyId: number;
        lastSignedPreKeyId?: number;
        signedIdentityKey: {
            private: string;
            public: string;
        };
        advSignedIdentity: {
            details: BrowserAuthBufferJson;
            accountSignatureKey: BrowserAuthBufferJson;
            accountSignature: BrowserAuthBufferJson;
            deviceSignature: BrowserAuthBufferJson;
        };
        preKeys: BrowserAuthPreKey[];
        signedPreKeys: BrowserAuthKeyPair[];
    };
};
export type BrowserAuthImportOptions = {
    name?: string;
    platform?: string;
};
export type BrowserAuthImport = {
    creds: AuthenticationCreds;
    keys: SignalDataSet;
    selectedNoiseCandidate: {
        privateIvIndex: number;
        publicIvIndex: number;
        recoveryTokenIvIndex?: number;
    };
};
export function makeBrowserAuthImport(extract: BrowserAuthExtract, options?: BrowserAuthImportOptions): BrowserAuthImport;
export function writeBrowserAuthToMultiFile(folder: string, extract: BrowserAuthExtract, options?: BrowserAuthImportOptions): Promise<BrowserAuthImport>;
export function extractWhatsAppWebAuthFromBrowser(): Promise<BrowserAuthExtract>;
