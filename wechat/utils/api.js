const { createWechatClient } = require('../sdk/index');
const { SERVER_BASE_URL } = require('../config');

let client;

function getClient() {
  if (!client) {
    client = createWechatClient({
      baseUrl: SERVER_BASE_URL
    });
  }
  return client;
}

function formatDetails(input, result) {
  return {
    requestPlain: input,
    requestCipher: result.cipherRequest,
    responsePlain: result.data,
    responseCipher: result.cipherResponse,
    responseHeaders: result.responseHeaders,
    requestHeaders: result.stcHeaders,
    latency: result.timings,
    encryptRequest: result.encryptRequest,
    decryptResponse: result.decryptResponse
  };
}

function fallbackErrorDetails(input, error, elapsedMs) {
  const responseHeaders = error && error.headers && Object.keys(error.headers).length > 0 ? error.headers : null;
  return formatDetails(input, {
    data: error && error.data !== undefined ? error.data : null,
    cipherRequest: null,
    cipherResponse: null,
    responseHeaders,
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

// Always resolves to { ok, error, details } so the page never inspects
// mutated Error objects; details is null when the failure produced none.
async function callApi(mode, input) {
  const startedAt = Date.now();
  try {
    const details = await getClient().sendDetailed({ mode, data: input });
    return { ok: true, error: null, details: formatDetails(input, details) };
  } catch (error) {
    const elapsedMs = Date.now() - startedAt;
    const details = error.details ? formatDetails(input, error.details) : fallbackErrorDetails(input, error, elapsedMs);
    return { ok: false, error, details };
  }
}

module.exports = { callApi };
