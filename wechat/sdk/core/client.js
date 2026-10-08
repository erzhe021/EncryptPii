const { SdkError, HttpError } = require('./errors');
const { MODES, KEY_ID_HEADER, SESSION_KEY_HEADER, ENCRYPTED_RESPONSE_HEADER } = require('./protocol');
const { createKeyManager } = require('./key-manager');
const { createCrypto } = require('./crypto');

const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

function normalizeHeaders(headers = {}) {
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) {
    throw new SdkError('INVALID_ARGUMENT', 'Headers must be an object');
  }
  const normalized = Object.create(null);
  for (const name of Object.keys(headers)) {
    if ([KEY_ID_HEADER.toLowerCase(), SESSION_KEY_HEADER.toLowerCase()]
      .includes(name.toLowerCase()) || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)
      || typeof headers[name] !== 'string' || /[\r\n]/.test(headers[name])) {
      throw new SdkError('INVALID_ARGUMENT', 'Invalid or reserved request header');
    }
    normalized[name.toLowerCase()] = headers[name];
  }
  return normalized;
}

function parseResult(response) {
  if (!response || typeof response !== 'object' || Array.isArray(response)
      || typeof response.code !== 'string' || !hasOwn(response, 'data')
    || (response.message !== null && typeof response.message !== 'string')) {
    throw new SdkError('INVALID_RESPONSE', 'Server response is not a valid Result');
  }
  return response;
}

// Reject oversized payloads before they reach the synchronous Forge
// routines; a multi-megabyte string would freeze the JS thread.
const MAX_PAYLOAD_BYTES = 1024 * 1024;

function serializeData(data) {
  let serialized;
  try {
    serialized = JSON.stringify(data);
  } catch (cause) {
    throw new SdkError('INVALID_ARGUMENT', 'Data must be JSON serializable', cause);
  }
  if (serialized === undefined) {
    throw new SdkError('INVALID_ARGUMENT', 'Data is not JSON serializable');
  }
  if (serialized.length > MAX_PAYLOAD_BYTES) {
    throw new SdkError('INVALID_ARGUMENT', `Payload exceeds ${MAX_PAYLOAD_BYTES} bytes`);
  }
  return serialized;
}

function isCipherEnvelope(value) {
  return Boolean(value) && typeof value === 'object'
    && (hasOwn(value, 'ivBase64') || hasOwn(value, 'encryptedDataBase64'));
}

function isKeyExpiredHttpError(error) {
  return Boolean(error) && typeof error === 'object'
    && error.statusCode === 400
    && Boolean(error.data) && typeof error.data === 'object'
    && error.data.code === 'KEY_EXPIRED' && Boolean(error.data.data);
}

function headerValue(headers, name) {
  if (!headers || typeof headers !== 'object') {
    return null;
  }
  const direct = headers[name] ?? headers[name.toLowerCase()];
  if (typeof direct === 'string' && direct.length > 0) {
    return direct;
  }
  for (const key of Object.keys(headers)) {
    if (key && key.toLowerCase() === name.toLowerCase()) {
      const value = headers[key];
      if (typeof value === 'string' && value.length > 0) {
        return value;
      }
    }
  }
  return null;
}

function isEncryptedResponse(headers, raw) {
  const flag = headerValue(headers, ENCRYPTED_RESPONSE_HEADER);
  if (flag !== null) {
    return /^true$/i.test(flag);
  }
  return Boolean(raw) && typeof raw === 'object' && isCipherEnvelope(raw);
}

function createClient(options) {
  if (!options || typeof options.transport !== 'function'
    || typeof options.randomBytes !== 'function') {
    throw new SdkError('INVALID_ARGUMENT', 'Transport and random source are required');
  }
  const validHttps = typeof options.baseUrl === 'string'
    && /^https:\/\/(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::[0-9]{1,5})?\/?$/.test(options.baseUrl);
  const validLocalHttp = typeof options.baseUrl === 'string'
    && /^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]{1,5})?\/?$/.test(options.baseUrl);
  if (!validHttps && !validLocalHttp) {
    throw new SdkError('INVALID_ARGUMENT',
      'HTTPS origin or a local HTTP origin is required');
  }
  const baseUrl = options.baseUrl.replace(/\/$/, '');
  const timeoutMs = options.timeoutMs === undefined ? 15000 : options.timeoutMs;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new SdkError('INVALID_ARGUMENT', 'Timeout must be a positive number');
  }
  const keyRefreshMarginMs = options.keyRefreshMarginMs === undefined ? 1000 : options.keyRefreshMarginMs;
  if (!Number.isFinite(keyRefreshMarginMs) || keyRefreshMarginMs < 0) {
    throw new SdkError('INVALID_ARGUMENT', 'Key refresh margin must be a non-negative number');
  }
  const defaultHeaders = normalizeHeaders(options.headers);
  const transport = options.transport;
  const crypto = createCrypto(options.randomBytes);

  async function fetchRaw(path, requestOptions) {
    let response;
    try {
      response = await transport({
        url: baseUrl + path,
        method: requestOptions.method || 'POST',
        data: requestOptions.data,
        timeoutMs,
        headers: {
          'content-type': 'application/json', ...defaultHeaders, ...requestOptions.headers
        }
      });
    } catch (cause) {
      if (cause instanceof SdkError) {
        throw cause;
      }
      throw new SdkError('NETWORK_ERROR', 'Network request failed', cause);
    }
    if (!response || !Number.isInteger(response.statusCode)) {
      throw new SdkError('INVALID_RESPONSE', 'Transport returned an invalid HTTP response');
    }
    const headers = response.headers || response.header || {};
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw new HttpError(response.statusCode, response.data, headers);
    }
    return { data: response.data, headers };
  }

  async function request(path, requestOptions) {
    const response = await fetchRaw(path, requestOptions);
    return response.data;
  }

  const keys = createKeyManager(request, keyRefreshMarginMs);

  async function sendOnce(mode, inputData, headers, serverKey, startedAt) {
    const encrypted = mode.encryptRequest || mode.decryptResponse;
    const encryptionStartedAt = Date.now();
    const session = encrypted
      ? await crypto.prepare(serializeData(inputData), serverKey, mode.encryptRequest) : null;
    const encryptionFinishedAt = Date.now();
    const body = mode.encryptRequest ? session.payload : inputData;
    const requestHeaders = Object.assign({}, headers);
    if (encrypted) {
      requestHeaders[KEY_ID_HEADER] = serverKey.keyId;
      requestHeaders[SESSION_KEY_HEADER] = session.encryptedSessionKeyBase64;
    }

    let raw;
    let responseHeaders = {};
    let httpError = null;
    try {
      const response = await fetchRaw(mode.endpoint, { data: body, headers: requestHeaders });
      raw = response.data;
      responseHeaders = response.headers;
    } catch (error) {
      if (!(error instanceof HttpError)) {
        throw error;
      }
      httpError = error;
      raw = error.data;
      responseHeaders = error.headers;
    }
    const httpFinishedAt = Date.now();

    const decryptResponse = mode.decryptResponse && isEncryptedResponse(responseHeaders, raw);

    let value = raw;
    let responseError = null;
    if (decryptResponse) {
      try {
        value = crypto.decrypt(raw, session.sessionKey);
      } catch (error) {
        if (!(error instanceof SdkError)) {
          throw error;
        }
        responseError = error;
        value = null;
      }
    }
    if (!responseError && !httpError) {
      try {
        parseResult(value);
      } catch (error) {
        if (!(error instanceof SdkError)) {
          throw error;
        }
        responseError = error;
      }
    }

    const finishedAt = Date.now();
    const details = {
      data: value,
      encryptRequest: mode.encryptRequest,
      decryptResponse: mode.decryptResponse,
      cipherRequest: mode.encryptRequest ? body : null,
      cipherResponse: decryptResponse ? raw : null,
      responseHeaders: responseHeaders && Object.keys(responseHeaders).length > 0 ? responseHeaders : null,
      stcHeaders: encrypted
        ? {
          [KEY_ID_HEADER]: requestHeaders[KEY_ID_HEADER],
          [SESSION_KEY_HEADER]: requestHeaders[SESSION_KEY_HEADER]
        }
        : null,
      timings: {
        total: finishedAt - startedAt,
        encryption: encrypted ? encryptionFinishedAt - encryptionStartedAt : 0,
        http: httpFinishedAt - encryptionFinishedAt,
        decryption: decryptResponse ? finishedAt - httpFinishedAt : 0
      }
    };
    return { details, httpError, responseError };
  }

  async function execute(input, detailed) {
    if (!input || !hasOwn(MODES, input.mode)) {
      throw new SdkError('INVALID_ARGUMENT', 'Unknown transport mode');
    }
    const mode = MODES[input.mode];
    const headers = normalizeHeaders(input.headers);
    const startedAt = Date.now();
    const encrypted = mode.encryptRequest || mode.decryptResponse;
    let serverKey = encrypted ? await keys.get(headers) : null;

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const { details, httpError, responseError } =
        await sendOnce(mode, input.data, headers, serverKey, startedAt);
      if (httpError && encrypted && attempt === 0 && isKeyExpiredHttpError(httpError)) {
        if (typeof console !== 'undefined' && typeof console.log === 'function') {
          console.log('Server key expired, attempting to install new key...',
            JSON.stringify(httpError.data));
        }
        try {
          serverKey = keys.install(httpError.data.data);
          continue;
        } catch (cause) {
          if (!(cause instanceof SdkError) || cause.code !== 'INVALID_SERVER_KEY') {
            throw cause;
          }
        }
      }
      const failure = responseError || httpError;
      if (failure) {
        if (detailed) {
          failure.details = details;
        }
        throw failure;
      }
      return detailed ? details : details.data;
    }
  }

  return {
    send: (input) => execute(input, false),
    sendDetailed: (input) => execute(input, true)
  };
}

module.exports = { createClient };
