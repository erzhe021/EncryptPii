const { SdkError } = require('./errors');
const { PUBLIC_KEY_PATH } = require('./protocol');

function createKeyManager(request) {
  let cached = null;
  let fetching = null;

  function install(key) {
    if (!key || typeof key.keyId !== 'string' || !key.keyId
      || typeof key.publicKeyBase64 !== 'string' || !key.publicKeyBase64
      || !Number.isFinite(key.expiresAtEpochMillis)
      || key.expiresAtEpochMillis <= Date.now()) {
      throw new SdkError('INVALID_SERVER_KEY', 'Server public key is invalid or expired');
    }
    cached = {
      keyId: key.keyId,
      publicKeyBase64: key.publicKeyBase64,
      expiresAtEpochMillis: key.expiresAtEpochMillis
    };
    return cached;
  }

  function get(headers) {
    if (cached && cached.expiresAtEpochMillis > Date.now()) {
      return Promise.resolve(cached);
    }
    if (!fetching) {
      fetching = request(PUBLIC_KEY_PATH, { method: 'GET', headers })
        .then((key) => {
          // A concurrent KEY_EXPIRED response may already have installed a newer key.
          if (cached && cached.expiresAtEpochMillis > Date.now()) {
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
