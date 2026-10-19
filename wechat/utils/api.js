const { SdkError } = require('../sdk/index');
const { REQUESTS } = require('../config');
const { getClient } = require('./clients');

function encodeFormComponent(value) {
  return encodeURIComponent(value)
    .replace(/[!'()~]/g, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`)
    .replace(/%20/g, '+');
}

function formatRequestPlain(input, contentType) {
  if (contentType !== 'application/x-www-form-urlencoded') {
    return formatResult(input);
  }
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return formatResult(input);
  }
  return Object.entries(input)
    .map(([key, value]) => `${encodeFormComponent(key)}=${encodeFormComponent(String(value))}`)
    .join('&');
}

function formatResult(value) {
  return typeof value === 'string' ? value : JSON.stringify(value, null, 2);
}

function formatDetails(input, result, contentType) {
  return {
    requestPlain: formatRequestPlain(input, contentType),
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
    return { ok: true, error: null, details: formatDetails(input, details, request.contentType) };
  } catch (error) {
    const elapsedMs = Date.now() - startedAt;
    const request = REQUESTS[requestName];
    const details = error.details
      ? formatDetails(input, error.details, request && request.contentType)
      : fallbackErrorDetails(input, error, elapsedMs, request && request.contentType);
    return { ok: false, error, details };
  }
}

function fallbackErrorDetails(input, error, elapsedMs, contentType) {
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
  }, contentType);
}

module.exports = { callApi };
