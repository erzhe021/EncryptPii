const forge = require('../lib/forge.min.js');
const { SdkError } = require('./errors');
const { SESSION_KEY_BYTES, IV_BYTES, TAG_BYTES, OAEP_SEED_BYTES } = require('./protocol');

function decodeBase64(value) {
  if (typeof value !== 'string' || !value
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new SdkError('INVALID_CIPHER_PAYLOAD', 'Invalid Base64 payload');
  }
  return forge.util.decode64(value);
}

function createCrypto(randomBytes) {
  let cachedBase64 = null;
  let cachedPublicKey = null;

  async function random(length) {
    let bytes;
    try {
      bytes = await randomBytes(length);
    } catch (cause) {
      if (cause instanceof SdkError) {
        throw cause;
      }
      throw new SdkError('RANDOM_UNAVAILABLE', 'Secure randomness unavailable', cause);
    }
    if (Object.prototype.toString.call(bytes) !== '[object Uint8Array]'
      || bytes.length !== length) {
      throw new SdkError('RANDOM_UNAVAILABLE', 'Random source returned invalid bytes');
    }
    let binary = '';
    for (const element of bytes) {
      binary += String.fromCodePoint(element);
    }
    return binary;
  }

  function publicKey(serverKey) {
    if (cachedBase64 !== serverKey.publicKeyBase64) {
      try {
          cachedPublicKey = forge.pki.publicKeyFromAsn1(
            forge.asn1.fromDer(decodeBase64(serverKey.publicKeyBase64))
        );
        cachedBase64 = serverKey.publicKeyBase64;
      } catch (cause) {
        throw new SdkError('INVALID_SERVER_KEY', 'Cannot parse server public key', cause);
      }
    }
    return cachedPublicKey;
  }

  async function prepare(data, serverKey, encryptBody) {
    const key = publicKey(serverKey);
    const sessionKey = await random(SESSION_KEY_BYTES);
    const seed = await random(OAEP_SEED_BYTES);
    let encryptedSessionKeyBase64;
    try {
      encryptedSessionKeyBase64 = forge.util.encode64(key.encrypt(sessionKey, 'RSA-OAEP', {
        md: forge.md.sha256.create(),
        mgf1: { md: forge.md.sha1.create() },
        seed
      }));
    } catch (cause) {
      throw new SdkError('ENCRYPTION_FAILED', 'Session key encryption failed', cause);
    }
    if (!encryptBody) {
      return { sessionKey, encryptedSessionKeyBase64 };
    }
    const iv = await random(IV_BYTES);
    const cipher = forge.cipher.createCipher('AES-GCM', sessionKey);
    cipher.start({ iv, tagLength: TAG_BYTES * 8 });
    cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(data)));
    if (!cipher.finish()) {
      throw new SdkError('ENCRYPTION_FAILED', 'Request encryption failed');
    }
    return {
      sessionKey,
      payload: {
        ivBase64: forge.util.encode64(iv),
        encryptedDataBase64: forge.util.encode64(
          cipher.output.getBytes() + cipher.mode.tag.getBytes()
        )
      },
      encryptedSessionKeyBase64
    };
  }

  function decrypt(payload, sessionKey) {
    if (!payload || typeof payload !== 'object') {
      throw new SdkError('INVALID_CIPHER_PAYLOAD', 'Invalid encrypted response');
    }
    const data = decodeBase64(payload.encryptedDataBase64);
    const iv = decodeBase64(payload.ivBase64);
    if (data.length < TAG_BYTES || iv.length !== IV_BYTES) {
      throw new SdkError('INVALID_CIPHER_PAYLOAD', 'Invalid encrypted response lengths');
    }
    const decipher = forge.cipher.createDecipher('AES-GCM', sessionKey);
    decipher.start({
      iv, tag: forge.util.createBuffer(data.slice(-TAG_BYTES)), tagLength: TAG_BYTES * 8
    });
    decipher.update(forge.util.createBuffer(data.slice(0, -TAG_BYTES)));
    if (!decipher.finish()) {
      throw new SdkError('DECRYPTION_FAILED', 'Response authentication failed');
    }
    try {
      return JSON.parse(forge.util.decodeUtf8(decipher.output.getBytes()));
    } catch (cause) {
      throw new SdkError('INVALID_RESPONSE', 'Decrypted response is not valid JSON', cause);
    }
  }

  return { prepare, decrypt };
}

module.exports = { createCrypto };
