import makeWASocket from './Socket/index.js';
export * from '../WAProto/index.js';
// exported so consumers can wrap/override config.makeSignalRepository without
// deep-importing lib/Signal/libsignal.js
export { makeLibSignalRepository } from './Signal/libsignal.js';
export * from './Utils/index.js';
export * from './Types/index.js';
export * from './Store/index.js';
export * from './Defaults/index.js';
export * from './WABinary/index.js';
export * from './WAM/index.js';
export * from './WAUSync/index.js';
export { makeWASocket };
export default makeWASocket;
//# sourceMappingURL=index.js.map