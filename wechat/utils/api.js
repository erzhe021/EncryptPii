const { request, HttpError } = require('./request');
const {
  ensureRandomPool,
  encryptRequest,
  encryptResponseOnlySessionKey,
  decryptResponse
} = require('./crypto');

const ENDPOINTS = {
  plain: '/plain/server/normal',
  bidirectional: '/crypto/server/bidirectional',
  'request-only': '/crypto/server/request-only',
  'response-only': '/crypto/server/response-only'
};

// 模式行为矩阵：是否加密请求体 / 是否解密响应体
const ENCRYPTS_REQUEST = {
  bidirectional: true,
  'request-only': true
};
const DECRYPTS_RESPONSE = {
  bidirectional: true,
  'response-only': true
};

// ---------- 服务器公钥管理 ----------

let cachedServerKey = null;
let fetchingServerKey = null;

function validateServerKey(key) {
  if (!key || !key.publicKeyBase64 || !key.keyId
    || !Number.isFinite(key.expiresAtEpochMillis)
    || key.expiresAtEpochMillis <= Date.now()) {
    throw new Error('Kong 返回的公钥信息无效或已过期');
  }
  return key;
}

function cacheServerKey(key) {
  cachedServerKey = validateServerKey(key);
  return cachedServerKey;
}

function isUsable(key) {
  return Boolean(key) && key.expiresAtEpochMillis > Date.now();
}

function fetchServerKey() {
  // 并发去重：多个请求同时需要公钥时只发起一次网络请求
  if (!fetchingServerKey) {
    fetchingServerKey = request('/crypto/server/public-key', { method: 'GET' })
      .then(cacheServerKey)
      .finally(() => {
        fetchingServerKey = null;
      });
  }
  return fetchingServerKey;
}

async function getServerKey() {
  if (isUsable(cachedServerKey)) {
    return cachedServerKey;
  }
  return fetchServerKey();
}

// 服务端在 KEY_EXPIRED 错误体中携带最新公钥，可直接用于重试
function extractKeyFromError(error) {
  if (error instanceof HttpError && error.statusCode === 400
    && error.data && error.data.code === 'KEY_EXPIRED' && error.data.data) {
    return error.data.data;
  }
  return null;
}

// ---------- 请求构造与结果组装 ----------

function buildEncryptedRequest(mode, input, serverKey) {
  if (mode === 'response-only') {
    const session = encryptResponseOnlySessionKey(serverKey);
    return {
      sessionKey: session.sessionKey,
      body: input,
      cipherRequest: null,
      header: {
        'X-STC-KEY-ID': serverKey.keyId,
        'X-STC-SESSION-KEY': session.encryptedSessionKeyBase64
      }
    };
  }

  const encrypted = encryptRequest(input, serverKey);
  return {
    sessionKey: encrypted.sessionKey,
    body: encrypted.payload,
    cipherRequest: encrypted.payload,
    header: null
  };
}

function makeResult(mode, input, cipherRequest, response, cipherResponse, timings) {
  return {
    request: ENCRYPTS_REQUEST[mode]
      ? { plain: input, cipher: cipherRequest }
      : input,
    response: DECRYPTS_RESPONSE[mode]
      ? { plain: response, cipher: cipherResponse }
      : response,
    'latency in ms': timings
  };
}

// ---------- 对外入口 ----------

async function sendEncrypted(mode, input) {
  const startedAt = Date.now();
  let serverKey = await getServerKey();

  for (let attempt = 0; attempt < 2; attempt += 1) {
    // 每次尝试（含 KEY_EXPIRED 重试）前确保随机池充足
    await ensureRandomPool();

    const encryptionStartedAt = Date.now();
    const encrypted = buildEncryptedRequest(mode, input, serverKey);
    const encryptionFinishedAt = Date.now();

    try {
      const rawResponse = await request(ENDPOINTS[mode], {
        data: encrypted.body,
        header: encrypted.header
      });
      const httpFinishedAt = Date.now();

      let response = rawResponse;
      let cipherResponse = null;
      let decryptionFinishedAt = httpFinishedAt;
      if (DECRYPTS_RESPONSE[mode]) {
        cipherResponse = rawResponse;
        response = JSON.parse(decryptResponse(rawResponse, encrypted.sessionKey));
        decryptionFinishedAt = Date.now();
      }

      return makeResult(mode, input, encrypted.cipherRequest, response, cipherResponse, {
        total: decryptionFinishedAt - startedAt,
        encryption: encryptionFinishedAt - encryptionStartedAt,
        http: httpFinishedAt - encryptionFinishedAt,
        decryption: decryptionFinishedAt - httpFinishedAt
      });
    } catch (error) {
      const latestKey = extractKeyFromError(error);
      if (!latestKey || attempt > 0) {
        throw error;
      }
      try {
        serverKey = cacheServerKey(latestKey);
      } catch (cacheError) {
        // 错误体中携带的公钥不可用时，抛出原始 KEY_EXPIRED 错误而非转换异常
        throw error;
      }
    }
  }

  throw new Error('加密请求重试失败');
}

async function callApi(mode, input) {
  if (!ENDPOINTS[mode]) {
    throw new Error(`未知的传输模式：${mode}`);
  }

  if (mode === 'plain') {
    const startedAt = Date.now();
    const response = await request(ENDPOINTS.plain, { data: input });
    const finishedAt = Date.now();
    return makeResult(mode, input, null, response, null, {
      total: finishedAt - startedAt,
      encryption: 0,
      http: finishedAt - startedAt,
      decryption: 0
    });
  }

  return sendEncrypted(mode, input);
}

module.exports = {
  callApi
};
