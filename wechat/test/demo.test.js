const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const vm = require('node:vm');
const forge = require('../sdk/lib/forge.min');
const { HttpError } = require('../sdk');
const { SDK_OPTIONS, REQUESTS } = require('../config');

test('demo maps all business requests to four SDK modes and preserves diagnostics', async () => {
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privateKey = forge.pki.privateKeyFromPem(pair.privateKey.export({
    type: 'pkcs8', format: 'pem'
  }));
  const key = {
    keyId: 'demo',
    publicKeyBase64: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    expiresAtEpochMillis: Date.now() + 600000,
    refreshAtEpochMillis: Date.now() + 300000
  };
  const previousWx = global.wx;
  const requests = [];
  let expectedRequest;
  let statusCode;
  let responseBody;
  let transportError;
  global.wx = {
    getRandomValues(request) {
      request.success({ randomValues: crypto.randomBytes(request.length) });
    },
    request(request) {
      try {
        requests.push(request);
        assert.equal(request.timeout, SDK_OPTIONS.timeoutMs);
        if (request.method === 'GET') {
          assert.equal(request.url, SDK_OPTIONS.baseUrl + SDK_OPTIONS.publicKeyPath);
          request.success({ statusCode: 200, data: key });
          return;
        }
        assert.equal(request.url, SDK_OPTIONS.baseUrl + expectedRequest.endpoint);
        const encryptRequest = ['bidirectional', 'request-only'].includes(expectedRequest.mode);
        const decryptResponse = ['bidirectional', 'response-only'].includes(expectedRequest.mode);
        let sessionKey;
        if (expectedRequest.mode !== 'plain') {
          assert.equal(request.header['X-STC-Key-Id'], key.keyId);
          const block = crypto.privateDecrypt(
            { key: pair.privateKey, padding: crypto.constants.RSA_NO_PADDING },
            Buffer.from(request.header['X-STC-Session-Key'], 'base64')
          );
          sessionKey = Buffer.from(forge.pkcs1.decode_rsa_oaep(
            privateKey, block.toString('binary'),
            { md: forge.md.sha256.create(), mgf1: { md: forge.md.sha1.create() } }
          ), 'binary');
        }
        if (encryptRequest) {
          const encrypted = Buffer.from(request.data.encryptedDataBase64, 'base64');
          const decipher = crypto.createDecipheriv(
            'aes-256-gcm', sessionKey, Buffer.from(request.data.ivBase64, 'base64')
          );
          decipher.setAuthTag(encrypted.subarray(-16));
          const plaintext = Buffer.concat([
            decipher.update(encrypted.subarray(0, -16)), decipher.final()
          ]).toString();
          assert.equal(JSON.parse(plaintext).name, '张三');
        } else {
          assert.deepEqual(JSON.parse(JSON.stringify(request.data)), { data: 'hello world' });
        }
        let data = responseBody;
        if (decryptResponse) {
          const iv = crypto.randomBytes(12);
          const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
          data = {
            ivBase64: iv.toString('base64'),
            encryptedDataBase64: Buffer.concat([
              cipher.update(JSON.stringify(responseBody)), cipher.final(), cipher.getAuthTag()
            ]).toString('base64')
          };
        }
        request.success({
          statusCode, data, header: { 'X-STC-Encrypted': String(decryptResponse) }
        });
      } catch (error) {
        transportError = error;
        request.fail(error);
      }
    }
  };
  try {
    const api = require('../utils/api');
    const source = fs.readFileSync(require.resolve('../pages/index/index.js'), 'utf8');
    for (const [name, configuration] of Object.entries(REQUESTS)) {
      expectedRequest = configuration;
      statusCode = name.endsWith('/client-exception') ? 400
        : name.endsWith('/system-exception') ? 500 : 200;
      responseBody = statusCode === 200
        ? { code: name.endsWith('/business-exception') ? 'business-error' : '0',
          message: null, data: { received: true } }
        : { status: statusCode, message: 'demo error' };
      let page;
      vm.runInNewContext(source, {
        require(path) {
          if (path === '../../utils/api') return api;
          if (path === '../../sdk/core/errors') return { HttpError };
          throw new Error(`Unexpected import: ${path}`);
        },
        Page(definition) { page = definition; }
      });
      page.setData = function (values) { Object.assign(this.data, values); };
      assert.ok(page.data.modes.some((entry) => entry.id === name));
      page.selectMode({ currentTarget: { dataset: { mode: name } } });
      const encryptRequest = ['bidirectional', 'request-only'].includes(configuration.mode);
      const decryptResponse = ['bidirectional', 'response-only'].includes(configuration.mode);
      assert.equal(page.data.usesPlainInput, !encryptRequest);
      await page.submit();
      assert.ifError(transportError);
      assert.equal(page.data.error, statusCode === 200 ? '' : `请求失败（HTTP ${statusCode}）`);
      assert.equal(page.data.loading, false);
      assert.deepEqual(JSON.parse(page.data.result.responsePlain), responseBody);
      assert.equal(page.data.result.requestCipher === 'N/A', !encryptRequest);
      assert.equal(page.data.result.responseCipher === 'N/A', !decryptResponse);
      assert.equal(page.data.result.requestPlainLabel,
        encryptRequest ? '请求体明文' : '请求体明文(实发)');
      assert.equal(page.data.result.responseCipherLabel,
        decryptResponse ? '响应体密文(实收)' : '响应体密文');
      assert.ok(JSON.parse(page.data.result.latency).total >= 0);
      if (configuration.mode !== 'plain') {
        assert.ok(page.data.result.requestHeaders.includes('X-STC-Session-Key'));
      }
    }
    assert.equal(requests.filter((request) => request.method === 'GET').length, 1);
    assert.equal(requests.filter((request) => request.method === 'POST').length,
      Object.keys(REQUESTS).length);
    const count = requests.length;
    const failure = await api.callApi('unknown', {});
    assert.equal(failure.ok, false);
    assert.equal(failure.error.code, 'INVALID_ARGUMENT');
    assert.equal(requests.length, count);
  } finally {
    if (previousWx === undefined) delete global.wx;
    else global.wx = previousWx;
  }
});
