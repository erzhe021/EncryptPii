const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const vm = require('node:vm');
const forge = require('../sdk/lib/forge.min');
const { HttpError } = require('../sdk');
const { SDK_OPTIONS, REQUESTS } = require('../config');

for (const enabled of [false, true]) {
test(`demo preserves diagnostics across all modes with crypto.enabled=${enabled}`, async () => {
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
          assert.equal(request.header['X-STC-Enabled'], undefined);
          assert.equal(request.url, SDK_OPTIONS.baseUrl + SDK_OPTIONS.publicKeyPath);
          request.success({ statusCode: 200, data: key });
          return;
        }
        assert.equal(request.url, SDK_OPTIONS.baseUrl + expectedRequest.endpoint);
        assert.equal(request.header['content-type'],
          expectedRequest.contentType || 'application/json');
        const encryptRequest = enabled && ['bidirectional', 'request-only'].includes(expectedRequest.mode);
        const decryptResponse = enabled && ['bidirectional', 'response-only'].includes(expectedRequest.mode);
        assert.equal(request.header['X-STC-Enabled'], String(encryptRequest || decryptResponse));
        let sessionKey;
        if (encryptRequest || decryptResponse) {
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
          const encryptedPayload = expectedRequest.contentType === 'application/x-www-form-urlencoded'
            ? Object.fromEntries(new URLSearchParams(request.data))
            : request.data;
          const encrypted = Buffer.from(encryptedPayload.encryptedDataBase64, 'base64');
          const decipher = crypto.createDecipheriv(
            'aes-256-gcm', sessionKey, Buffer.from(encryptedPayload.ivBase64, 'base64')
          );
          decipher.setAuthTag(encrypted.subarray(-16));
          const plaintext = Buffer.concat([
            decipher.update(encrypted.subarray(0, -16)), decipher.final()
          ]).toString();
          if (expectedRequest.contentType === 'application/x-www-form-urlencoded') {
            assert.equal(plaintext,
              'name=%E5%BC%A0%E4%B8%89&phone=11111111111&email=zhangsan%40example.com&address=%E4%B8%8A%E6%B5%B7%E5%B8%82%E9%95%BF%E5%AE%81%E5%8C%BA%E6%9F%90%E6%9F%90%E5%B9%BF%E5%9C%BA%E5%8A%9E%E5%85%ACA%E6%A5%BC');
          } else {
            assert.equal(JSON.parse(plaintext).name, '张三');
          }
        } else if (['plain', 'response-only'].includes(expectedRequest.mode)) {
          assert.deepEqual(JSON.parse(JSON.stringify(request.data)), { data: 'hello world' });
        } else if (expectedRequest.contentType === 'application/x-www-form-urlencoded') {
          assert.equal(new URLSearchParams(request.data).get('name'), '张三');
        } else {
          assert.equal(request.data.name, '张三');
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
          statusCode,
          data,
          header: {
            'X-STC-Encrypted': String(decryptResponse),
            'content-type': 'application/json; charset=utf-8'
          }
        });
      } catch (error) {
        transportError = error;
        request.fail(error);
      }
    }
  };
  try {
    const apiModule = { exports: {} };
    vm.runInNewContext(fs.readFileSync(require.resolve('../utils/api'), 'utf8'), {
      require(path) {
        if (path === '../sdk/index') return require('../sdk');
        if (path === '../config') {
          return { REQUESTS, SDK_OPTIONS: { ...SDK_OPTIONS, crypto: { enabled } } };
        }
        throw new Error(`Unexpected import: ${path}`);
      },
      module: apiModule
    });
    const api = apiModule.exports;
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
      const encryptRequest = enabled && ['bidirectional', 'request-only'].includes(configuration.mode);
      const decryptResponse = enabled && ['bidirectional', 'response-only'].includes(configuration.mode);
      assert.equal(page.data.usesPlainInput,
        !['bidirectional', 'request-only'].includes(configuration.mode));
      await page.submit();
      assert.ifError(transportError);
      assert.equal(page.data.error, statusCode === 200 ? '' : `请求失败（HTTP ${statusCode}）`);
      assert.equal(page.data.loading, false);
      assert.deepEqual(JSON.parse(page.data.result.responsePlain), responseBody);
      assert.equal(JSON.parse(page.data.result.requestHeaders)['Content-Type'],
        configuration.contentType || 'application/json');
      assert.equal(JSON.parse(page.data.result.requestHeaders)['X-STC-Enabled'],
        String(encryptRequest || decryptResponse));
      assert.deepEqual(JSON.parse(page.data.result.responseHeaders), {
        'X-STC-Encrypted': String(decryptResponse),
        'Content-Type': 'application/json; charset=utf-8'
      });
      if (configuration.contentType === 'application/x-www-form-urlencoded') {
        assert.equal(page.data.result.requestPlain,
          'name=%E5%BC%A0%E4%B8%89&phone=11111111111&email=zhangsan%40example.com&address=%E4%B8%8A%E6%B5%B7%E5%B8%82%E9%95%BF%E5%AE%81%E5%8C%BA%E6%9F%90%E6%9F%90%E5%B9%BF%E5%9C%BA%E5%8A%9E%E5%85%ACA%E6%A5%BC');
      }
      assert.equal(page.data.result.requestCipher === 'N/A', !encryptRequest);
      assert.equal(page.data.result.responseCipher === 'N/A', !decryptResponse);
      assert.equal(page.data.result.requestPlainLabel,
        encryptRequest ? '请求体明文' : '请求体明文(实发)');
      assert.equal(page.data.result.responseCipherLabel,
        decryptResponse ? '响应体密文(实收)' : '响应体密文');
      assert.ok(JSON.parse(page.data.result.latency).total >= 0);
      if (encryptRequest || decryptResponse) {
        assert.ok(page.data.result.requestHeaders.includes('X-STC-Session-Key'));
      } else {
        assert.ok(!page.data.result.requestHeaders.includes('X-STC-Session-Key'));
      }
    }
    assert.equal(requests.filter((request) => request.method === 'GET').length, enabled ? 1 : 0);
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
}
