const { SdkError, HttpError } = require('./errors');
const { MODES, KEY_ID_HEADER, SESSION_KEY_HEADER } = require('./protocol');
const { createKeyManager } = require('./key-manager');
const { createCrypto } = require('./crypto');

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
    || typeof response.code !== 'string' || !Object.prototype.hasOwnProperty.call(response, 'data')
    || (response.message !== null && typeof response.message !== 'string')) {
    throw new SdkError('INVALID_RESPONSE', 'Server response is not a valid Result');
  }
  return response;
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
        headers: Object.assign(
          { 'content-type': 'application/json' }, defaultHeaders, requestOptions.headers
        )
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

  async function execute(input, detailed) {
    if (!input || !Object.prototype.hasOwnProperty.call(MODES, input.mode)) {
      throw new SdkError('INVALID_ARGUMENT', 'Unknown transport mode');
    }
    const mode = MODES[input.mode];
    const headers = normalizeHeaders(input.headers);
    let serialized;
    try {
      serialized = JSON.stringify(input.data);
      if (serialized === undefined) {
        throw new Error('Data is not JSON serializable');
      }
    } catch (cause) {
      throw new SdkError('INVALID_ARGUMENT', 'Data must be JSON serializable', cause);
    }
    // Snapshot the body so asynchronous key acquisition and retry use the same input.
    const data = JSON.parse(serialized);
    const startedAt = Date.now();
    const encrypted = mode.encryptRequest || mode.decryptResponse;
    let serverKey = encrypted ? await keys.get(headers) : null;

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const encryptionStartedAt = Date.now();
      const session = encrypted
        ? await crypto.prepare(serialized, serverKey, mode.encryptRequest) : null;
      const encryptionFinishedAt = Date.now();
      const body = mode.encryptRequest ? session.payload : data;
      const requestHeaders = Object.assign({}, headers);
      if (encrypted && !mode.encryptRequest) {
        requestHeaders[KEY_ID_HEADER] = serverKey.keyId;
        requestHeaders[SESSION_KEY_HEADER] = session.encryptedSessionKeyBase64;
      }
      let raw;
      let httpError;
      try {
        raw = await request(mode.endpoint, { data: body, headers: requestHeaders });
      } catch (error) {
        if (!(error instanceof HttpError)) {
          throw error;
        }
        if (encrypted && attempt === 0 && error.statusCode === 400
          && error.data && error.data.code === 'KEY_EXPIRED' && error.data.data) {
          try {
            serverKey = keys.install(error.data.data);
            continue;
          } catch (cause) {
            if (!(cause instanceof SdkError) || cause.code !== 'INVALID_SERVER_KEY') {
              throw cause;
            }
          }
        }
        httpError = error;
        raw = error.data;
      }
      const httpFinishedAt = Date.now();
      // Gateway errors may be plaintext even when the endpoint encrypts responses.
      const decryptResponse = mode.decryptResponse && (!httpError || (raw
        && typeof raw === 'object'
        && (Object.prototype.hasOwnProperty.call(raw, 'ivBase64')
          || Object.prototype.hasOwnProperty.call(raw, 'encryptedDataBase64'))));
      const details = {
        data: null,
        cipherRequest: mode.encryptRequest ? body : null,
        cipherResponse: decryptResponse ? raw : null,
        stcHeaders: mode.decryptResponse && !mode.encryptRequest
          ? {
            [KEY_ID_HEADER]: requestHeaders[KEY_ID_HEADER],
            [SESSION_KEY_HEADER]: requestHeaders[SESSION_KEY_HEADER]
          }
          : null,
        timings: {
          total: 0,
          encryption: encrypted ? encryptionFinishedAt - encryptionStartedAt : 0,
          http: httpFinishedAt - encryptionFinishedAt,
          decryption: 0
        }
      };
      let responseError;
      try {
        const response = decryptResponse ? crypto.decrypt(raw, session.sessionKey) : raw;
        details.data = response;
        if (!httpError) {
          parseResult(response);
        }
      } catch (error) {
        if (!(error instanceof SdkError)) {
          throw error;
        }
        responseError = error;
      }
      const finishedAt = Date.now();
      details.timings.total = finishedAt - startedAt;
      details.timings.decryption = decryptResponse ? finishedAt - httpFinishedAt : 0;
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
