import * as staticStrategy from "./strategies/static.js";
import * as bearerPassthrough from "./strategies/bearer_passthrough.js";
import * as oauth2ClientCredentials from "./strategies/oauth2_client_credentials.js";
import * as oauth2Authcode from "./strategies/oauth2_authcode.js";
import * as deviceCode from "./strategies/device_code.js";

// The entire provider surface is this map: one strategy per auth *mechanism*,
// never per provider. A new provider (e.g. "Grok") that speaks
// oauth2_client_credentials needs zero new code here — only a new upstreams row.
const STRATEGIES = {
  static: staticStrategy,
  bearer_passthrough: bearerPassthrough,
  oauth2_client_credentials: oauth2ClientCredentials,
  oauth2_authcode: oauth2Authcode,
  device_code: deviceCode,
};

export async function resolveUpstreamToken({ descriptor, credentials, callerToken, decrypt, encrypt, saveCredentials }) {
  const strategy = STRATEGIES[descriptor.kind];
  if (!strategy) throw new Error(`unknown auth descriptor kind: ${descriptor.kind}`);
  return strategy.resolve({ descriptor, credentials, callerToken, decrypt, encrypt, saveCredentials });
}

export function injectCredential({ descriptor, token, headers, url }) {
  const value = descriptor.inject.template.replace("{token}", token);
  if (descriptor.inject.location === "header") {
    headers.set(descriptor.inject.name, value);
  } else if (descriptor.inject.location === "query") {
    url.searchParams.set(descriptor.inject.name, value);
  } else {
    throw new Error(`unknown inject location: ${descriptor.inject.location}`);
  }
}
