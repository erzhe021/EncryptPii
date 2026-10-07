const { createWechatClient } = require('../sdk/index');
const { KONG_BASE_URL } = require('../config');

let client;

function getClient() {
  if (!client) {
    client = createWechatClient({ baseUrl: KONG_BASE_URL });
  }
  return client;
}

function formatDetails(input, result) {
  return {
    requestPlain: input,
    requestCipher: result.cipherRequest,
    responsePlain: result.data,
    responseCipher: result.cipherResponse,
    requestHeaders: result.stcHeaders,
    latency: result.timings,
    encryptRequest: result.encryptRequest,
    decryptResponse: result.decryptResponse
  };
}

// Always resolves to { ok, error, details } so the page never inspects
// mutated Error objects; details is null when the failure produced none.
async function callApi(mode, input) {
  try {
    const details = await getClient().sendDetailed({ mode, data: input });
    return { ok: true, error: null, details: formatDetails(input, details) };
  } catch (error) {
    const details = error.details ? formatDetails(input, error.details) : null;
    return { ok: false, error, details };
  }
}

module.exports = { callApi };
