const { createWechatClient } = require('../sdk/index');
const { KONG_BASE_URL } = require('../config');

let client;

async function callApi(mode, input) {
  if (!client) {
    client = createWechatClient({ baseUrl: KONG_BASE_URL });
  }
  const result = await client.sendDetailed({ mode, data: input });
  return {
    request: result.cipherRequest ? { plain: input, cipher: result.cipherRequest } : input,
    response: result.cipherResponse
      ? { plain: result.data, cipher: result.cipherResponse } : result.data,
    'latency in ms': result.timings
  };
}

module.exports = { callApi };
