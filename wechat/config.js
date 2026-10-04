// Set this to the HTTPS origin where Kong is reachable.
// run this first: kubectl -n kong port-forward service/encryptpii-kong 18443:8443
// const KONG_BASE_URL = 'https://localhost:18443'; //do not pass through mitmproxy
const KONG_BASE_URL = 'https://local.kong.test:18443'; // pass through mitmproxy, refer to mitmproxy.md

module.exports = {
  KONG_BASE_URL
};
