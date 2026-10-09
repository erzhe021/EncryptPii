const forge = require('../lib/forge.min.js');
const { SdkError } = require('./errors');
const { PUBLIC_KEY_PATH } = require('./protocol');

function isUsable(key) {
  return Boolean(key) && key.refreshAtEpochMillis > Date.now();
}

// Parse the public key eagerly so a malformed replacement key surfaces
// during KEY_EXPIRED handling instead of the next encrypted request.
function verifyPublicKey(base64) {
  try {
    const der = forge.util.decode64(base64);
    forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(der));
  } catch (cause) {
    throw new SdkError('INVALID_SERVER_KEY',
      'Server public key is not a valid RSA SubjectPublicKeyInfo', cause);
  }
}

function createKeyManager(request) {
  let cached = null;
  let fetching = null;

  function install(key) {
    if (!key || typeof key.keyId !== 'string' || !key.keyId
      || typeof key.publicKeyBase64 !== 'string' || !key.publicKeyBase64
      || !Number.isFinite(key.expiresAtEpochMillis)
      || !Number.isFinite(key.refreshAtEpochMillis)
      || key.refreshAtEpochMillis > key.expiresAtEpochMillis
      || key.expiresAtEpochMillis <= Date.now()) {
      throw new SdkError('INVALID_SERVER_KEY', 'Server public key is invalid or expired');
    }
    verifyPublicKey(key.publicKeyBase64);
    cached = {
      keyId: key.keyId,
      publicKeyBase64: key.publicKeyBase64,
      expiresAtEpochMillis: key.expiresAtEpochMillis,
      refreshAtEpochMillis: key.refreshAtEpochMillis
    };
    return cached;
  }

  function get(headers) {
    if (isUsable(cached)) {
      return Promise.resolve(cached);
    }
    if (!fetching) {
      fetching = request(PUBLIC_KEY_PATH, { method: 'GET', headers })
        .then((key) => {
          // A concurrent KEY_EXPIRED response may already have installed a newer key.
          if (isUsable(cached)) {
            return cached;
          }
          return install(key);
        })
        .finally(() => { fetching = null; });
    }
    return fetching;
  }

  return { get, install };
}

module.exports = { createKeyManager };
