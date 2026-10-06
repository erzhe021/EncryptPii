const { createWechatClient } = require('../sdk/index');
const { KONG_BASE_URL } = require('../config');

let client;

async function callApi(mode, input) {
  if (!client) {
    client = createWechatClient({ baseUrl: KONG_BASE_URL });
  }
  const result = await client.sendDetailed({ mode, data: input });
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
