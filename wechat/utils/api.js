const { createWechatClient } = require('../sdk/index');
const { KONG_BASE_URL } = require('../config');

let client;

async function callApi(mode, input) {
  if (!client) {
    client = createWechatClient({ baseUrl: KONG_BASE_URL });
  }
  try {
    const result = await client.sendDetailed({ mode, data: input });
    return formatDetails(input, result);
  } catch (error) {
    if (error.details) {
      error.result = formatDetails(input, error.details);
    }
    throw error;
  }
}

function formatDetails(input, result) {
  return {
    requestPlain: input,
    requestCipher: result.cipherRequest,
    responsePlain: result.data,
    responseCipher: result.cipherResponse,
    stcHeaders: result.stcHeaders,
    latency: result.timings
  };
}

module.exports = { callApi };
