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
      try {
        raw = await request(mode.endpoint, { data: body, headers: requestHeaders });
      } catch (error) {
        if (!encrypted || attempt !== 0 || !(error instanceof HttpError)
          || error.statusCode !== 400 || !error.data || error.data.code !== 'KEY_EXPIRED'
          || !error.data.data) {
          throw error;
        }
        try {
          serverKey = keys.install(error.data.data);
        } catch (cause) {
          if (!(cause instanceof SdkError) || cause.code !== 'INVALID_SERVER_KEY') {
            throw cause;
          }
          throw error;
        }
        continue;
      }
      const httpFinishedAt = Date.now();
      const response = parseResult(mode.decryptResponse ? crypto.decrypt(raw, session.sessionKey) : raw);
      const finishedAt = Date.now();
      if (!detailed) {
        return response;
      }
      return {
        data: response,
        cipherRequest: mode.encryptRequest ? body : null,
        cipherResponse: mode.decryptResponse ? raw : null,
        timings: {
          total: finishedAt - startedAt,
          encryption: encrypted ? encryptionFinishedAt - encryptionStartedAt : 0,
          http: httpFinishedAt - encryptionFinishedAt,
          decryption: mode.decryptResponse ? finishedAt - httpFinishedAt : 0
        }
      };
    }
    throw new SdkError('KEY_RETRY_FAILED', 'Server key retry failed');
  }

  return {
    send: (input) => execute(input, false),
    sendDetailed: (input) => execute(input, true)
  };
}

module.exports = { createClient };
