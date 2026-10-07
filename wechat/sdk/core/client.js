const { SdkError, HttpError } = require('./errors');
const { MODES, KEY_ID_HEADER, SESSION_KEY_HEADER } = require('./protocol');
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

function serializeData(data) {
  try {
    const serialized = JSON.stringify(data);
    if (serialized === undefined) {
      throw new Error('Data is not JSON serializable');
    }
    return serialized;
  } catch (cause) {
    throw new SdkError('INVALID_ARGUMENT', 'Data must be JSON serializable', cause);
  }
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

function createClient(options) {
  if (!options || typeof options.baseUrl !== 'string'
    || !/^https:\/\/(?:\[[0-9a-fA-F:]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?)(?::[0-9]{1,5})?\/?$/.test(options.baseUrl)
    || typeof options.transport !== 'function'
    || typeof options.randomBytes !== 'function') {
    throw new SdkError('INVALID_ARGUMENT', 'HTTPS origin, transport and random source are required');
  }
  const baseUrl = options.baseUrl.replace(/\/$/, '');
  const timeoutMs = options.timeoutMs === undefined ? 15000 : options.timeoutMs;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new SdkError('INVALID_ARGUMENT', 'Timeout must be a positive number');
  }
  const defaultHeaders = normalizeHeaders(options.headers);
  const transport = options.transport;
  const crypto = createCrypto(options.randomBytes);

  async function request(path, requestOptions) {
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
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw new HttpError(response.statusCode, response.data);
    }
    return response.data;
  }

  const keys = createKeyManager(request);

  // Performs one full attempt (encryption, transport, decryption) and never
  // throws for HTTP or response-shape failures; the caller decides on retries.
  async function sendOnce(mode, serialized, data, headers, serverKey, startedAt) {
    const encrypted = mode.encryptRequest || mode.decryptResponse;
    const encryptionStartedAt = Date.now();
    const session = encrypted
      ? await crypto.prepare(serialized, serverKey, mode.encryptRequest) : null;
    const encryptionFinishedAt = Date.now();
    const body = mode.encryptRequest ? session.payload : data;
    const requestHeaders = Object.assign({}, headers);
    if (encrypted) {
      requestHeaders[KEY_ID_HEADER] = serverKey.keyId;
      requestHeaders[SESSION_KEY_HEADER] = session.encryptedSessionKeyBase64;
    }

    let raw;
    let httpError = null;
    try {
      raw = await request(mode.endpoint, { data: body, headers: requestHeaders });
    } catch (error) {
      if (!(error instanceof HttpError)) {
        throw error;
      }
      httpError = error;
      raw = error.data;
    }
    const httpFinishedAt = Date.now();

    // Gateway errors may be plaintext even when the endpoint encrypts responses.
    const decryptResponse = mode.decryptResponse && (!httpError || isCipherEnvelope(raw));
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
    const serialized = serializeData(input.data);
    // Snapshot the body so asynchronous key acquisition and retry use the same input.
    const data = JSON.parse(serialized);
    const startedAt = Date.now();
    const encrypted = mode.encryptRequest || mode.decryptResponse;
    let serverKey = encrypted ? await keys.get(headers) : null;

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const { details, httpError, responseError } =
        await sendOnce(mode, serialized, data, headers, serverKey, startedAt);
      if (httpError && encrypted && attempt === 0 && isKeyExpiredHttpError(httpError)) {
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
    throw new SdkError('KEY_RETRY_FAILED', 'Server key retry failed');
  }

  return {
    send: (input) => execute(input, false),
    sendDetailed: (input) => execute(input, true)
  };
}

module.exports = { createClient };
