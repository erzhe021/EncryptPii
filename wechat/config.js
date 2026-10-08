// Direct Java Server by default; use a reachable HTTPS origin on real devices.
const SERVER_BASE_URL = 'http://localhost:9090';

module.exports = {
  SERVER_BASE_URL,
  KEY_REFRESH_MARGIN_MS: 30000 // 30 seconds
};
