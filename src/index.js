// Library entry. Deliberately free of any storage or server import so a host
// embedding okeydokey's credential handling does not drag in libsql, the GUI
// bundle, or an HTTP listener.
export * from "./keyring/index.js";
export { resolveUpstreamToken, injectCredential } from "./auth/engine.js";
