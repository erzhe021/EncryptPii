// forge 会通过 `self` / `window` 探测宿主环境，
// 微信小程序逻辑层两者都不存在，需先在全局对象上补齐 `self`。
if (typeof globalThis !== 'undefined' && typeof globalThis.self === 'undefined') {
  globalThis.self = globalThis;
}

const forge = require('../lib/forge.min.js');

// wx.getRandomValues 是异步 API，而 forge（RSA-OAEP 填充）需要同步取随机数，
// 因此维护一个异步预取的随机字节池，加密前通过 ensureRandomPool() 确保充足。
const POOL_SIZE = 4096;
const POOL_MIN_REMAINING = 512;

// AES-GCM 认证标签长度（与 Kong 插件约定保持一致）
const GCM_TAG_BITS = 128;
const GCM_TAG_BYTES = GCM_TAG_BITS / 8;

let pool = '';
let poolOffset = 0;
let poolFilling = null;

function toBinaryString(view) {
  let bytes = '';
  for (let index = 0; index < view.length; index += 1) {
    bytes += String.fromCharCode(view[index]);
  }
  return bytes;
}

// 小程序 API 返回的 ArrayBuffer 可能来自其他 JS 上下文，
// 跨上下文时 instanceof 会失效，改用 toString 结构化判断 + 鸭子类型兜底。
function toUint8Array(randomValues) {
  if (!randomValues) {
    return null;
  }
  const tag = Object.prototype.toString.call(randomValues);
  if (tag === '[object ArrayBuffer]') {
    return new Uint8Array(randomValues);
  }
  if (tag === '[object Uint8Array]') {
    return randomValues;
  }
  const viewTags = ['[object Int8Array]', '[object Uint8ClampedArray]', '[object Uint16Array]',
    '[object Int16Array]', '[object Uint32Array]', '[object Int32Array]',
    '[object Float32Array]', '[object Float64Array]'];
  if (viewTags.indexOf(tag) !== -1) {
    return new Uint8Array(
      randomValues.buffer,
      randomValues.byteOffset,
      randomValues.byteLength
    );
  }
  if (Array.isArray(randomValues)) {
    return new Uint8Array(randomValues);
  }
  // 兜底：Uint8Array 构造器可直接接受 ArrayBuffer / TypedArray / Array
  if (typeof randomValues.byteLength === 'number' || typeof randomValues.length === 'number') {
    try {
      const view = new Uint8Array(randomValues);
      if (view.length > 0) {
        return view;
      }
    } catch (error) {
      // 转换失败则返回 null
    }
  }
  return null;
}

function fetchRandomBytes(length) {
  return new Promise((resolve, reject) => {
    if (typeof wx.getRandomValues !== 'function') {
      reject(new Error('当前微信基础库不支持安全随机数，请升级微信客户端'));
      return;
    }
    wx.getRandomValues({
      length,
      success(res) {
        const view = toUint8Array(res && res.randomValues);
        if (!view || view.length !== length) {
          console.error('getRandomValues 返回异常，实际类型：',
            Object.prototype.toString.call(res && res.randomValues), res);
          reject(new Error('无法获取安全随机数'));
        } else {
          resolve(view);
        }
      },
      fail(err) {
        console.error('getRandomValues 调用失败：', err);
        reject(new Error((err && err.errMsg) || '无法获取安全随机数'));
      }
    });
  });
}

function refillPool() {
  if (!poolFilling) {
    poolFilling = fetchRandomBytes(POOL_SIZE)
      .then((view) => {
        const remaining = poolOffset < pool.length ? pool.slice(poolOffset) : '';
        pool = remaining + toBinaryString(view);
        poolOffset = 0;
        poolFilling = null;
      })
      .catch((error) => {
        poolFilling = null;
        throw error;
      });
  }
  return poolFilling;
}

function ensureRandomPool() {
  if (pool.length - poolOffset < POOL_MIN_REMAINING) {
    return refillPool();
  }
  return Promise.resolve();
}

function randomBytes(length) {
  if (pool.length - poolOffset < length) {
    throw new Error('安全随机数不足，请重试');
  }
  const bytes = pool.slice(poolOffset, poolOffset + length);
  poolOffset += length;
  return bytes;
}

forge.random.getBytesSync = randomBytes;
forge.random.getBytes = function getBytes(length, callback) {
  const bytes = randomBytes(length);
  if (callback) {
    callback(null, bytes);
    return undefined;
  }
  return bytes;
};

// RSA 公钥解析开销较大，按 keyId 缓存解析结果，避免每次加密封包都重复解析。
const parsedKeyCache = { keyId: null, publicKey: null };

function getParsedPublicKey(serverKey) {
  if (parsedKeyCache.keyId !== serverKey.keyId) {
    const der = forge.util.decode64(serverKey.publicKeyBase64);
    parsedKeyCache.publicKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(der));
    parsedKeyCache.keyId = serverKey.keyId;
  }
  return parsedKeyCache.publicKey;
}

function encryptSessionKey(sessionKey, serverPublicKey) {
  return serverPublicKey.encrypt(sessionKey, 'RSA-OAEP', {
    md: forge.md.sha256.create(),
    mgf1: { md: forge.md.sha1.create() }
  });
}

function encryptRequest(data, serverKey) {
  const sessionKey = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = forge.cipher.createCipher('AES-GCM', sessionKey);
  cipher.start({ iv, tagLength: GCM_TAG_BITS });
  cipher.update(forge.util.createBuffer(forge.util.encodeUtf8(JSON.stringify(data))));
  if (!cipher.finish()) {
    throw new Error('请求加密失败');
  }
  const encryptedData = cipher.output.getBytes() + cipher.mode.tag.getBytes();
  const publicKey = getParsedPublicKey(serverKey);

  return {
    sessionKey,
    payload: {
      keyId: serverKey.keyId,
      encryptedSessionKeyBase64: forge.util.encode64(encryptSessionKey(sessionKey, publicKey)),
      ivBase64: forge.util.encode64(iv),
      encryptedDataBase64: forge.util.encode64(encryptedData)
    }
  };
}

function encryptResponseOnlySessionKey(serverKey) {
  const sessionKey = randomBytes(32);
  const publicKey = getParsedPublicKey(serverKey);
  return {
    sessionKey,
    encryptedSessionKeyBase64: forge.util.encode64(encryptSessionKey(sessionKey, publicKey))
  };
}

function decryptResponse(payload, sessionKey) {
  const encryptedData = forge.util.decode64(payload.encryptedDataBase64);
  if (encryptedData.length < GCM_TAG_BYTES) {
    throw new Error('加密响应格式无效');
  }
  const ciphertext = encryptedData.slice(0, -GCM_TAG_BYTES);
  const tag = encryptedData.slice(-GCM_TAG_BYTES);
  const decipher = forge.cipher.createDecipher('AES-GCM', sessionKey);
  decipher.start({
    iv: forge.util.decode64(payload.ivBase64),
    tag: forge.util.createBuffer(tag),
    tagLength: GCM_TAG_BITS
  });
  decipher.update(forge.util.createBuffer(ciphertext));
  if (!decipher.finish()) {
    throw new Error('响应认证或解密失败');
  }
  return forge.util.decodeUtf8(decipher.output.getBytes());
}

// 模块加载时预热随机池，降低首次加密请求的等待时间（失败静默，加密前会再重试）。
refillPool().catch(() => {});

module.exports = {
  ensureRandomPool,
  encryptRequest,
  encryptResponseOnlySessionKey,
  decryptResponse
};
