const { KONG_BASE_URL } = require('../config');

const DEFAULT_TIMEOUT_MS = 15000;

class HttpError extends Error {
  constructor(statusCode, data) {
    const detail = typeof data === 'string' ? data : JSON.stringify(data);
    super(`请求失败（HTTP ${statusCode}）${detail ? `：${detail}` : ''}`);
    this.statusCode = statusCode;
    this.data = data;
  }
}

function request(path, options) {
  const baseUrl = KONG_BASE_URL.replace(/\/+$/, '');
  if (!baseUrl || baseUrl.includes('your-kong-domain.example.com')) {
    return Promise.reject(new Error('请先在 config.js 中配置 Kong 服务地址'));
  }

  const requestOptions = options || {};
  return new Promise((resolve, reject) => {
    wx.request({
      url: `${baseUrl}${path}`,
      method: requestOptions.method || 'POST',
      data: requestOptions.data,
      timeout: requestOptions.timeout || DEFAULT_TIMEOUT_MS,
      header: Object.assign(
        { 'content-type': 'application/json' },
        requestOptions.header || {}
      ),
      success(response) {
        if (response.statusCode >= 200 && response.statusCode < 300) {
          resolve(response.data);
          return;
        }
        reject(new HttpError(response.statusCode, response.data));
      },
      fail(error) {
        reject(new Error(error.errMsg || '网络请求失败'));
      }
    });
  });
}

module.exports = {
  request,
  HttpError
};
