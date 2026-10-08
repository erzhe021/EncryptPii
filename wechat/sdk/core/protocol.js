const MODES = Object.freeze({
  plain: Object.freeze({
    endpoint: '/plain/server/normal', encryptRequest: false, decryptResponse: false
  }),
  bidirectional: Object.freeze({
    endpoint: '/crypto/server/bidirectional', encryptRequest: true, decryptResponse: true
  }),
  'request-only': Object.freeze({
    endpoint: '/crypto/server/request-only', encryptRequest: true, decryptResponse: false
  }),
  'response-only': Object.freeze({
    endpoint: '/crypto/server/response-only', encryptRequest: false, decryptResponse: true
  }),
  'response-only/client-exception': Object.freeze({
    endpoint: '/crypto/server/response-only/client-exception',
    encryptRequest: false, decryptResponse: true
  }),
  'response-only/system-exception': Object.freeze({
    endpoint: '/crypto/server/response-only/system-exception',
    encryptRequest: false, decryptResponse: true
  }),
  'response-only/business-exception': Object.freeze({
    endpoint: '/crypto/server/response-only/business-exception',
    encryptRequest: false, decryptResponse: true
  })
});

module.exports = {
  MODES,
  PUBLIC_KEY_PATH: '/crypto/server/public-key',
  KEY_ID_HEADER: 'X-STC-Key-Id',
  SESSION_KEY_HEADER: 'X-STC-Session-Key',
  ENCRYPTED_RESPONSE_HEADER: 'X-STC-Encrypted',
  SESSION_KEY_BYTES: 32,
  IV_BYTES: 12,
  TAG_BYTES: 16,
  OAEP_SEED_BYTES: 32
};
