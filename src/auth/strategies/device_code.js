// device_code: RFC 8628. Like oauth2_authcode, the initial device-grant + user
// approval happens once via the GUI (src/gui/device-flow.js); this resolves ongoing
// refresh only, generic across every device-auth provider.
export { resolve } from "./oauth2_authcode.js";
