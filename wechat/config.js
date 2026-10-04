// Set this to the HTTPS origin where Kong is reachable.
// run this first: kubectl -n kong port-forward service/encryptpii-kong 18443:8443
const KONG_BASE_URL = 'https://localhost:18443';

module.exports = {
  KONG_BASE_URL
};
