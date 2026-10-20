const { SdkError } = require('../sdk/index');
const { REQUESTS } = require('../config');
const { getClient } = require('./clients');

function formatResult(value) {
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

function formatDetails(input, result) {
  return {
    requestPlain: formatResult(input),
    requestCipher: result.cipherRequest,
    responsePlain: result.data,
    responseCipher: result.cipherResponse,
    responseHeaders: result.responseHeaders,
    requestHeaders: result.requestHeaders,
    latency: result.timings,
    encryptRequest: result.encryptRequest,
    decryptResponse: result.decryptResponse
  };
}

// Always resolves to { ok, error, details } so the page never inspects
// mutated Error objects; details is null when the failure produced none.
async function callApi(requestName, input, headers) {
  const startedAt = Date.now();
  try {
    if (!Object.prototype.hasOwnProperty.call(REQUESTS, requestName)) {
      throw new SdkError('INVALID_ARGUMENT', 'Unknown application request');
    }
    const { service, ...request } = REQUESTS[requestName];
    const details = await getClient(service).sendDetailed({ ...request, headers, data: input });
    return { ok: true, error: null, details: formatDetails(input, details) };
  } catch (error) {
    const elapsedMs = Date.now() - startedAt;
    const request = REQUESTS[requestName];
    const details = error.details
      ? formatDetails(input, error.details)
      : fallbackErrorDetails(input, error, elapsedMs);
    return { ok: false, error, details };
  }
}

function fallbackErrorDetails(input, error, elapsedMs) {
  const responseHeaders = error && error.headers && Object.keys(error.headers).length > 0 ? error.headers : null;
  return formatDetails(input, {
    data: error && error.data !== undefined ? error.data : null,
    cipherRequest: null,
    cipherResponse: null,
    responseHeaders,
    requestHeaders: null,
    stcHeaders: null,
    timings: {
      total: elapsedMs >= 0 ? elapsedMs : 0,
      encryption: 0,
      http: elapsedMs >= 0 ? elapsedMs : 0,
      decryption: 0
    },
    encryptRequest: false,
    decryptResponse: false
  });
}

module.exports = { callApi };
