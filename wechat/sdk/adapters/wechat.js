const { SdkError } = require('../core/errors');
const { createClient } = require('../core/client');

// WeChat's wx.getRandomValues caps single calls far below this; rejecting
// early avoids the platform's silent failure modes.
const MAX_RANDOM_BYTES = 16384;

function globalPlatform() {
  return typeof wx !== 'undefined' ? wx : null;
}

function createWechatAdapter(platform) {
  if (!platform || typeof platform.request !== 'function') {
    throw new SdkError('INVALID_ARGUMENT', 'A WeChat request API is required');
  }
  function transport(options) {
    return new Promise((resolve, reject) => {
      platform.request({
        url: options.url,
        method: options.method,
        data: options.data,
        timeout: options.timeoutMs,
        header: options.headers,
        success: resolve,
        fail(cause) {
          reject(new SdkError('NETWORK_ERROR', 'Network request failed', cause));
        }
      });
    });
  }
  function randomBytes(length) {
    return new Promise((resolve, reject) => {
      if (!platform || typeof platform.getRandomValues !== 'function') {
        reject(new SdkError('RANDOM_UNAVAILABLE', 'Upgrade WeChat to support secure randomness'));
        return;
      }
      if (!Number.isInteger(length) || length <= 0 || length > MAX_RANDOM_BYTES) {
        reject(new SdkError('RANDOM_UNAVAILABLE',
          `Random length must be an integer in [1, ${MAX_RANDOM_BYTES}]`));
        return;
      }
      platform.getRandomValues({
        length,
        success(response) {
          const values = response ? response.randomValues : undefined;
          let bytes;
          if (Object.prototype.toString.call(values) === '[object ArrayBuffer]') {
            bytes = new Uint8Array(values);
          } else if (ArrayBuffer.isView(values)) {
            bytes = new Uint8Array(values.buffer, values.byteOffset, values.byteLength);
          }
          if (!bytes || bytes.length !== length) {
            reject(new SdkError('RANDOM_UNAVAILABLE', 'WeChat returned invalid random bytes'));
            return;
          }
          resolve(bytes);
        },
        fail(cause) {
          reject(new SdkError('RANDOM_UNAVAILABLE', 'Secure randomness unavailable', cause));
        }
      });
    });
  }
  return { transport, randomBytes };
}

function createWechatClient(options) {
  const platform = (options && options.platform) || globalPlatform();
  const adapter = createWechatAdapter(platform);
  return createClient(Object.assign({}, options, adapter));
}

module.exports = { createWechatAdapter, createWechatClient };
