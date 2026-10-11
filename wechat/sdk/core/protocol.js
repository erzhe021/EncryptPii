const MODES = Object.freeze({
  'plain': Object.freeze({
    encryptRequest: false, decryptResponse: false
  }),
  'bidirectional': Object.freeze({
    encryptRequest: true, decryptResponse: true
  }),
  'request-only': Object.freeze({
    encryptRequest: true, decryptResponse: false
  }),
  'response-only': Object.freeze({
    encryptRequest: false, decryptResponse: true
  })
});

module.exports = {
  MODES,
  KEY_ID_HEADER: 'X-STC-Key-Id',
  SESSION_KEY_HEADER: 'X-STC-Session-Key',
  ENCRYPTED_RESPONSE_HEADER: 'X-STC-Encrypted',
  SESSION_KEY_BYTES: 32,
  IV_BYTES: 12,
  TAG_BYTES: 16,
  OAEP_SEED_BYTES: 32
};
