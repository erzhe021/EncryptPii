const test = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const vm = require('node:vm');
const { createClient, createWechatClient, createWechatAdapter, SdkError, HttpError } = require('..');
const forge = require('../lib/forge.min');

function makeKey(id) {
  const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    privateKey: pair.privateKey,
    info: {
      keyId: id,
      publicKeyBase64: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
      expiresAtEpochMillis: Date.now() + 600000
    }
  };
}

const firstKey = makeKey('first');
const secondKey = makeKey('second');
const randomBytes = async (length) => new Uint8Array(nodeCrypto.randomBytes(length));

function xor(left, right) {
  return Buffer.from(left.map((value, index) => value ^ right[index]));
}

function mgf1(seed, length) {
  const blocks = [];
  for (let counter = 0; blocks.length * 20 < length; counter += 1) {
    const count = Buffer.alloc(4);
    count.writeUInt32BE(counter);
    blocks.push(nodeCrypto.createHash('sha1').update(seed).update(count).digest());
  }
  return Buffer.concat(blocks).subarray(0, length);
}

// Node's OAEP API cannot configure MGF1 independently. Decode with Node's raw
// RSA and SHA primitives to check SHA-256 + MGF1-SHA-1 independently of Forge.
function unwrapSession(encoded, key) {
  const block = nodeCrypto.privateDecrypt(
    { key: key.privateKey, padding: nodeCrypto.constants.RSA_NO_PADDING },
    Buffer.from(encoded, 'base64')
  );
  assert.equal(block[0], 0);
  const maskedSeed = block.subarray(1, 33);
  const maskedDb = block.subarray(33);
  const seed = xor(maskedSeed, mgf1(maskedDb, 32));
  const db = xor(maskedDb, mgf1(seed, maskedDb.length));
  assert.deepEqual(db.subarray(0, 32), nodeCrypto.createHash('sha256').update('').digest());
  const separator = db.indexOf(1, 32);
  assert.ok(separator >= 32);
  assert.ok(db.subarray(32, separator).every((value) => value === 0));
  const sessionKey = db.subarray(separator + 1);
  assert.equal(sessionKey.length, 32);
  return sessionKey;
}

function decryptBody(payload, sessionKey) {
  const data = Buffer.from(payload.encryptedDataBase64, 'base64');
  const iv = Buffer.from(payload.ivBase64, 'base64');
  assert.equal(iv.length, 12);
  const cipher = nodeCrypto.createDecipheriv('aes-256-gcm', sessionKey, iv);
  cipher.setAuthTag(data.subarray(-16));
  return JSON.parse(Buffer.concat([cipher.update(data.subarray(0, -16)), cipher.final()]).toString());
}

function encryptResponse(data, sessionKey) {
  const iv = nodeCrypto.randomBytes(12);
  const cipher = nodeCrypto.createCipheriv('aes-256-gcm', sessionKey, iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(data), 'utf8'), cipher.final(), cipher.getAuthTag()
  ]);
  return { ivBase64: iv.toString('base64'), encryptedDataBase64: encrypted.toString('base64') };
}

function result(data) {
  return { code: '0', message: null, data };
}

function options(transport, extra) {
  return Object.assign({ baseUrl: 'https://kong.example.com', transport, randomBytes }, extra);
}

function gateway(key, requests, sessions) {
  return async (request) => {
    requests.push(request);
    if (request.method === 'GET') {
      return { statusCode: 200, data: key.info };
    }
    const mode = request.url.split('/').pop();
    if (mode === 'normal') {
      return { statusCode: 200, data: result(request.data) };
    }
    const session = unwrapSession(
      mode === 'response-only' ? request.headers['X-STC-SESSION-KEY']
        : request.data.encryptedSessionKeyBase64, key
    );
    sessions.push(session.toString('hex'));
    assert.equal(mode === 'response-only' ? request.headers['X-STC-KEY-ID'] : request.data.keyId,
      key.info.keyId);
    const body = mode === 'response-only' ? request.data : decryptBody(request.data, session);
    return {
      statusCode: 200,
      data: mode === 'request-only' ? result(body) : encryptResponse(result(body), session)
    };
  };
}

test('all modes preserve routing and interoperate with independent RSA/AES primitives', async () => {
  const requests = [];
  const sessions = [];
  const client = createClient(options(gateway(firstKey, requests, sessions)));
  const data = { name: '测试用户', nested: [null, 123, 'hello 🌍'] };
  const expected = result(data);
  for (const mode of ['plain', 'bidirectional', 'request-only', 'response-only']) {
    assert.deepEqual(await client.send({ mode, data }), expected);
    const detailed = await client.sendDetailed({ mode, data });
    assert.deepEqual(detailed.data, expected);
    assert.equal(Boolean(detailed.cipherRequest), ['bidirectional', 'request-only'].includes(mode));
    assert.equal(Boolean(detailed.cipherResponse), ['bidirectional', 'response-only'].includes(mode));
    if (mode === 'response-only') {
      assert.equal(detailed.stcHeaders['X-STC-KEY-ID'], firstKey.info.keyId);
      assert.ok(detailed.stcHeaders['X-STC-SESSION-KEY']);
    } else {
      assert.equal(detailed.stcHeaders, null);
    }
    assert.equal(Object.hasOwn(detailed, 'sessionKey'), false);
    assert.equal(Object.hasOwn(detailed, 'request'), false);
    assert.ok(Object.values(detailed.timings).every((value) => value >= 0));
  }
  assert.equal(requests.filter((request) => request.method === 'GET').length, 1);
  assert.equal(new Set(sessions).size, 6);
});

test('plain requests do not require random support or fetch public keys', async () => {
  let count = 0;
  const client = createWechatClient({
    baseUrl: 'https://localhost:18443',
    platform: {
      request(request) {
        count += 1;
        assert.equal(request.url, 'https://localhost:18443/plain/server/normal');
        request.success({ statusCode: 200, data: result({ ok: true }) });
      }
    }
  });
  assert.deepEqual(await client.send({ mode: 'plain', data: {} }), result({ ok: true }));
  assert.equal(count, 1);
});

test('successful business responses must use the Result envelope', async () => {
  const client = createClient(options(async () => ({ statusCode: 200, data: { ok: true } })));
  await assert.rejects(client.send({ mode: 'plain', data: {} }), { code: 'INVALID_RESPONSE' });
});

test('concurrent encrypted calls share only key fetches, not session material', async () => {
  const requests = [];
  const sessions = [];
  const client = createClient(options(gateway(firstKey, requests, sessions)));
  const results = await Promise.all(Array.from({ length: 10 }, (_, index) =>
    client.send({ mode: 'bidirectional', data: { index } })));
  assert.deepEqual(results, Array.from({ length: 10 }, (_, index) => result({ index })));
  assert.equal(requests.filter((request) => request.method === 'GET').length, 1);
  assert.equal(new Set(sessions).size, 10);
});

test('clients with the same keyId keep keys and configuration isolated', async () => {
  const sameId = { ...secondKey, info: { ...secondKey.info, keyId: firstKey.info.keyId } };
  const requestsA = [];
  const requestsB = [];
  const a = createClient(options(gateway(firstKey, requestsA, [])));
  const b = createClient(options(gateway(sameId, requestsB, []), { baseUrl: 'https://other.example.com' }));
  await Promise.all([
    a.send({ mode: 'bidirectional', data: { client: 'a' } }),
    b.send({ mode: 'bidirectional', data: { client: 'b' } })
  ]);
  assert.ok(requestsA.every((request) => request.url.startsWith('https://kong.example.com/')));
  assert.ok(requestsB.every((request) => request.url.startsWith('https://other.example.com/')));
});

for (const mode of ['bidirectional', 'request-only', 'response-only']) {
  test(`${mode} retries KEY_EXPIRED once with fresh material and the supplied key`, async () => {
    let posts = 0;
    let gets = 0;
    let originalSession;
    const requests = [];
    const sessions = [];
    const newKey = { ...secondKey, info: { ...secondKey.info, keyId: firstKey.info.keyId } };
    const next = gateway(newKey, requests, sessions);
    const client = createClient(options(async (request) => {
      if (request.method === 'GET') {
        gets += 1;
        return { statusCode: 200, data: firstKey.info };
      }
      posts += 1;
      if (posts === 1) {
        originalSession = unwrapSession(
          mode === 'response-only' ? request.headers['X-STC-SESSION-KEY']
            : request.data.encryptedSessionKeyBase64, firstKey
        ).toString('hex');
        return { statusCode: 400, data: { code: 'KEY_EXPIRED', data: newKey.info } };
      }
      return next(request);
    }));
    assert.deepEqual(await client.send({ mode, data: { ok: true } }), result({ ok: true }));
    assert.equal(posts, 2);
    assert.equal(gets, 1);
    assert.notEqual(originalSession, sessions[0]);
    await client.send({ mode, data: {} });
    assert.equal(gets, 1);
  });
}

test('second KEY_EXPIRED and other HTTP failures are never replayed', async () => {
  for (const [statusCode, data, expectedPosts] of [
    [400, { code: 'KEY_EXPIRED', data: secondKey.info }, 2],
    [400, { code: 'KEY_EXPIRED', data: { ...secondKey.info, expiresAtEpochMillis: 0 } }, 1],
    [400, { code: 'KEY_EXPIRED' }, 1],
    [400, { code: 'INVALID_KEY' }, 1],
    [500, { secret: 'must not appear in error message' }, 1]
  ]) {
    let posts = 0;
    const client = createClient(options(async (request) => {
      if (request.method === 'GET') return { statusCode: 200, data: firstKey.info };
      posts += 1;
      return { statusCode, data };
    }));
    await assert.rejects(client.send({ mode: 'request-only', data: {} }), (error) => {
      assert.ok(error instanceof HttpError);
      assert.equal(error.statusCode, statusCode);
      assert.equal(error.data, data);
      assert.equal(error.message.includes('secret'), false);
      return true;
    });
    assert.equal(posts, expectedPosts);
  }
});

test('plain KEY_EXPIRED does not trigger encrypted retry', async () => {
  let count = 0;
  const client = createClient(options(async () => {
    count += 1;
    return { statusCode: 400, data: { code: 'KEY_EXPIRED', data: secondKey.info } };
  }));
  await assert.rejects(client.send({ mode: 'plain', data: {} }), { code: 'HTTP_ERROR' });
  assert.equal(count, 1);
});

test('detailed HTTP failures retain diagnostics and decrypt error bodies in every mode', async () => {
  for (const mode of ['plain', 'bidirectional', 'request-only', 'response-only']) {
    for (const statusCode of [400, 500]) {
      const data = { name: 'demo' };
      const errorBody = { status: statusCode, error: 'Failure', message: 'demo error' };
      let posts = 0;
      let raw;
      const client = createClient(options(async (request) => {
        if (request.method === 'GET') return { statusCode: 200, data: firstKey.info };
        posts += 1;
        raw = errorBody;
        if (mode === 'bidirectional' || mode === 'response-only') {
          const session = unwrapSession(mode === 'response-only'
            ? request.headers['X-STC-SESSION-KEY']
            : request.data.encryptedSessionKeyBase64, firstKey);
          raw = encryptResponse(errorBody, session);
        }
        return { statusCode, data: raw };
      }));
      await assert.rejects(client.sendDetailed({ mode, data }), (error) => {
        assert.ok(error instanceof HttpError);
        assert.equal(error.statusCode, statusCode);
        assert.equal(error.data, raw);
        assert.deepEqual(error.details.data, errorBody);
        assert.equal(Boolean(error.details.cipherRequest),
          ['bidirectional', 'request-only'].includes(mode));
        assert.equal(error.details.cipherResponse,
          ['bidirectional', 'response-only'].includes(mode) ? raw : null);
        assert.equal(Boolean(error.details.stcHeaders), mode === 'response-only');
        assert.ok(Object.values(error.details.timings).every((value) => value >= 0));
        assert.equal(Object.hasOwn(error.details, 'sessionKey'), false);
        return true;
      });
      assert.equal(posts, 1);
      await assert.rejects(client.send({ mode, data }), (error) => {
        assert.ok(error instanceof HttpError);
        assert.equal(Object.hasOwn(error, 'details'), false);
        return true;
      });
    }
  }
});

test('encrypted modes display plaintext HTTP failures without attempting decryption', async () => {
  for (const mode of ['bidirectional', 'response-only']) {
    const errorBody = { message: 'gateway failure' };
    const client = createClient(options(async (request) => request.method === 'GET'
      ? { statusCode: 200, data: firstKey.info }
      : { statusCode: 502, data: errorBody }));
    await assert.rejects(client.sendDetailed({ mode, data: {} }), (error) => {
      assert.equal(error.code, 'HTTP_ERROR');
      assert.deepEqual(error.details.data, errorBody);
      assert.equal(error.details.cipherResponse, null);
      assert.equal(error.details.timings.decryption, 0);
      return true;
    });
  }
});

test('failed error response authentication retains ciphertext without inventing plaintext', async () => {
  const raw = { ivBase64: Buffer.alloc(12).toString('base64'),
    encryptedDataBase64: Buffer.alloc(16).toString('base64') };
  const client = createClient(options(async (request) => request.method === 'GET'
    ? { statusCode: 200, data: firstKey.info }
    : { statusCode: 500, data: raw }));
  await assert.rejects(client.sendDetailed({ mode: 'bidirectional', data: {} }), (error) => {
    assert.equal(error.code, 'DECRYPTION_FAILED');
    assert.equal(error.details.data, null);
    assert.equal(error.details.cipherResponse, raw);
    assert.ok(error.details.cipherRequest);
    assert.ok(error.details.timings.total >= 0);
    return true;
  });
});

test('response-only exception requests route, transport session headers and decrypt errors', async () => {
  const fs = require('node:fs');
  const source = fs.readFileSync(require.resolve('../../pages/index/index.js'), 'utf8');
  for (const [variant, statusCode] of [
    ['client-exception', 400], ['system-exception', 500], ['business-exception', 200]
  ]) {
    const mode = `response-only/${variant}`;
    const response = statusCode === 200
      ? { code: 'code-123', message: 'business error', data: null }
      : { status: statusCode, message: 'server error' };
    let posts = 0;
    const client = createClient(options(async (request) => {
      if (request.method === 'GET') return { statusCode: 200, data: firstKey.info };
      posts += 1;
      assert.equal(request.url, `https://kong.example.com/crypto/server/${mode}`);
      assert.deepEqual(request.data, { data: 'hello world' });
      assert.equal(request.headers['X-STC-KEY-ID'], firstKey.info.keyId);
      const session = unwrapSession(request.headers['X-STC-SESSION-KEY'], firstKey);
      return { statusCode, data: encryptResponse(response, session) };
    }));
    let page;
    vm.runInNewContext(source, {
      require: () => ({
        callApi: async (selectedMode, data) => {
          let details;
          let failure;
          try {
            details = await client.sendDetailed({ mode: selectedMode, data });
          } catch (error) {
            failure = error;
            details = error.details;
          }
          const result = {
            requestPlain: data, requestCipher: details.cipherRequest,
            responsePlain: details.data, responseCipher: details.cipherResponse,
            stcHeaders: details.stcHeaders, latency: details.timings
          };
          if (failure) {
            failure.result = result;
            throw failure;
          }
          return result;
        }
      }),
      Page: (definition) => { page = definition; }
    });
    page.setData = function (values) { Object.assign(this.data, values); };
    assert.ok(page.data.modes.some((entry) => entry.id === mode));
    page.selectMode({ currentTarget: { dataset: { mode } } });
    assert.equal(page.data.usesPlainInput, true);
    await page.submit();
    assert.equal(posts, 1);
    assert.equal(page.data.error, statusCode === 200 ? '' : `请求失败（HTTP ${statusCode}）`);
    assert.equal(page.data.loading, false);
    assert.equal(page.data.result.requestCipher, 'N/A');
    assert.ok(page.data.result.requestPlain.includes('X-STC-SESSION-KEY'));
    assert.ok(page.data.result.responseCipher.includes('encryptedDataBase64'));
    assert.deepEqual(JSON.parse(page.data.result.responsePlain), response);
    assert.ok(JSON.parse(page.data.result.latency).total >= 0);
    assert.equal(page.data.result.requestPlainLabel, '请求明文（实发）');
    assert.equal(page.data.result.responseCipherLabel, '响应密文（实收）');
  }
});

test('demo page renders all five sections alongside the HTTP failure message', async () => {
  const fs = require('node:fs');
  const source = fs.readFileSync(require.resolve('../../pages/index/index.js'), 'utf8');
  for (const mode of ['plain', 'bidirectional', 'request-only', 'response-only']) {
    let page;
    const requestCipher = ['bidirectional', 'request-only'].includes(mode)
      ? { encryptedDataBase64: 'request' } : null;
    const responseCipher = ['bidirectional', 'response-only'].includes(mode)
      ? { encryptedDataBase64: 'response' } : null;
    const failure = new HttpError(500, {});
    failure.result = {
      requestPlain: { name: 'demo' }, requestCipher,
      responsePlain: { status: 500, message: 'demo error' }, responseCipher,
      stcHeaders: { 'X-STC-KEY-ID': 'first', 'X-STC-SESSION-KEY': 'wrapped' },
      latency: { total: 10, encryption: 2, http: 7, decryption: 1 }
    };
    vm.runInNewContext(source, {
      require: () => ({ callApi: async () => { throw failure; } }),
      Page: (definition) => { page = definition; }
    });
    page.setData = function (values) { Object.assign(this.data, values); };
    page.data.mode = mode;
    await page.submit();
    assert.equal(page.data.error, '请求失败（HTTP 500）');
    assert.equal(page.data.loading, false);
    assert.ok(page.data.result.requestPlain.includes('demo'));
    assert.equal(page.data.result.requestCipher,
      requestCipher ? JSON.stringify(requestCipher, null, 2) : 'N/A');
    assert.equal(page.data.result.responseCipher,
      responseCipher ? JSON.stringify(responseCipher, null, 2) : 'N/A');
    assert.ok(page.data.result.responsePlain.includes('demo error'));
    assert.ok(page.data.result.latency.includes('10'));
  }
});

test('network failures have stable errors and are not retried', async () => {
  let posts = 0;
  const cause = new Error('timeout');
  const client = createClient(options(async (request) => {
    if (request.method === 'GET') return { statusCode: 200, data: firstKey.info };
    posts += 1;
    throw cause;
  }));
  await assert.rejects(client.send({ mode: 'request-only', data: {} }), (error) => {
    assert.equal(error.code, 'NETWORK_ERROR');
    assert.equal(error.cause, cause);
    return true;
  });
  assert.equal(posts, 1);
});

test('key fetching recovers from failure and expired keys are not cached', async () => {
  let gets = 0;
  const next = gateway(firstKey, [], []);
  const client = createClient(options(async (request) => {
    if (request.method === 'GET' && ++gets === 1) {
      return { statusCode: 200, data: { ...firstKey.info, expiresAtEpochMillis: 0 } };
    }
    return next(request);
  }));
  await assert.rejects(client.send({ mode: 'request-only', data: {} }), { code: 'INVALID_SERVER_KEY' });
  assert.deepEqual(await client.send({ mode: 'request-only', data: { ok: true } }), result({ ok: true }));
  assert.equal(gets, 2);
});

test('body and headers are snapshotted before asynchronous key acquisition', async () => {
  let release;
  const next = gateway(firstKey, [], []);
  const client = createClient(options(async (request) => {
    if (request.method === 'GET') {
      await new Promise((resolve) => { release = resolve; });
    } else {
      assert.equal(request.headers.authorization, 'original');
    }
    return next(request);
  }));
  const data = { value: 'original' };
  const headers = { Authorization: 'original' };
  const pending = client.send({ mode: 'bidirectional', data, headers });
  data.value = 'changed';
  headers.Authorization = 'changed';
  release();
  assert.deepEqual(await pending, result({ value: 'original' }));
});

test('invalid configuration, JSON and reserved headers fail explicitly', async () => {
  const transport = async () => { throw new Error('should not send'); };
  for (const extra of [{ baseUrl: 'http://kong.example.com' }, { timeoutMs: 0 },
    { baseUrl: 'https://host\\unexpected' }, { headers: 'not an object' },
    { headers: { Authorization: 'token\r\nInjected: value' } },
    { headers: { 'x-stc-key-id': 'override' } }, { headers: { 'X-STC-SESSION-KEY': 'override' } }]) {
    assert.throws(() => createClient(options(transport, extra)), { code: 'INVALID_ARGUMENT' });
  }
  const client = createClient(options(transport));
  const circular = {};
  circular.self = circular;
  for (const input of [
    { mode: 'toString', data: {} }, { mode: '__proto__', data: {} },
    { mode: 'plain', data: undefined }, { mode: 'plain', data: circular },
    { mode: 'plain', data: {}, headers: 'not an object' },
    { mode: 'plain', data: {}, headers: { 'x-StC-SeSsIoN-kEy': 'override' } }
  ]) {
    await assert.rejects(client.send(input), { code: 'INVALID_ARGUMENT' });
  }
});

test('authentication headers merge case-insensitively without mutating configuration', async () => {
  const headers = { Authorization: 'default' };
  const client = createClient(options(async (request) => {
    assert.equal(request.headers.authorization, 'per-request');
    assert.equal(Object.keys(request.headers).filter((name) =>
      name.toLowerCase() === 'authorization').length, 1);
    assert.equal(request.headers['content-type'], 'application/json');
    assert.equal(request.timeoutMs, 1234);
    return { statusCode: 200, data: result({}) };
  }, { headers, timeoutMs: 1234 }));
  headers.Authorization = 'mutated';
  await client.send({ mode: 'plain', data: {}, headers: { authorization: 'per-request' } });
});

test('per-request authentication headers also reach public key acquisition', async () => {
  const next = gateway(firstKey, [], []);
  const client = createClient(options(async (request) => {
    assert.equal(request.headers.authorization, 'token');
    return next(request);
  }));
  await client.send({
    mode: 'request-only', data: {}, headers: { Authorization: 'token' }
  });
});

test('missing, malformed or failing random sources never send encrypted POST', async () => {
  for (const source of [
    async () => new Uint8Array(1),
    async () => Array(32).fill(0),
    async () => { throw new Error('random failed'); }
  ]) {
    let posts = 0;
    const client = createClient(options(async (request) => {
      if (request.method === 'GET') return { statusCode: 200, data: firstKey.info };
      posts += 1;
      return { statusCode: 200, data: result({}) };
    }, { randomBytes: source }));
    await assert.rejects(client.send({ mode: 'bidirectional', data: {} }), { code: 'RANDOM_UNAVAILABLE' });
    assert.equal(posts, 0);
  }
});

test('malformed, unauthenticated and non-JSON encrypted responses fail without retries', async () => {
  for (const failure of ['missing', 'base64', 'iv', 'tag', 'json']) {
    let posts = 0;
    const client = createClient(options(async (request) => {
      if (request.method === 'GET') return { statusCode: 200, data: firstKey.info };
      posts += 1;
      const session = unwrapSession(request.data.encryptedSessionKeyBase64, firstKey);
      let payload = encryptResponse({ ok: true }, session);
      if (failure === 'missing') payload = null;
      if (failure === 'base64') payload.encryptedDataBase64 = '*invalid*';
      if (failure === 'iv') payload.ivBase64 = Buffer.alloc(1).toString('base64');
      if (failure === 'tag') {
        const bytes = Buffer.from(payload.encryptedDataBase64, 'base64');
        bytes[bytes.length - 1] ^= 1;
        payload.encryptedDataBase64 = bytes.toString('base64');
      }
      if (failure === 'json') {
        const iv = nodeCrypto.randomBytes(12);
        const cipher = nodeCrypto.createCipheriv('aes-256-gcm', session, iv);
        payload = {
          ivBase64: iv.toString('base64'),
          encryptedDataBase64: Buffer.concat([
            cipher.update('not JSON'), cipher.final(), cipher.getAuthTag()
          ]).toString('base64')
        };
      }
      return { statusCode: 200, data: payload };
    }));
    await assert.rejects(client.send({ mode: 'bidirectional', data: {} }), {
      code: failure === 'tag' ? 'DECRYPTION_FAILED'
        : failure === 'json' ? 'INVALID_RESPONSE' : 'INVALID_CIPHER_PAYLOAD'
    });
    assert.equal(posts, 1);
  }
});

test('SDK import and encryption do not replace or invoke Forge random functions', async () => {
  const original = forge.random.getBytesSync;
  const originalAsync = forge.random.getBytes;
  forge.random.getBytesSync = () => { throw new Error('implicit Forge random'); };
  forge.random.getBytes = () => { throw new Error('implicit Forge random'); };
  try {
    const client = createClient(options(gateway(firstKey, [], [])));
    assert.deepEqual(await client.send({ mode: 'bidirectional', data: {} }), result({}));
  } finally {
    forge.random.getBytesSync = original;
    forge.random.getBytes = originalAsync;
  }
});

test('import is inert without a WeChat environment or random prewarming', () => {
  const imported = spawnSync(process.execPath, ['-e', `
    const assert = require('node:assert/strict');
    global.wx = {
      request() { throw new Error('network on import'); },
      getRandomValues() { throw new Error('random on import'); }
    };
    const forge = require('./lib/forge.min');
    const sync = forge.random.getBytesSync;
    const async = forge.random.getBytes;
    require('.');
    assert.equal(forge.random.getBytesSync, sync);
    assert.equal(forge.random.getBytes, async);
  `], { cwd: require('node:path').resolve(__dirname, '..'), encoding: 'utf8' });
  if (imported.error) throw imported.error;
  assert.equal(imported.status, 0, imported.stderr);
});

test('demo wrapper returns separate plaintext, ciphertext, and latency values', async () => {
  const previousWx = global.wx;
  const requests = [];
  const next = gateway(firstKey, requests, []);
  global.wx = {
    getRandomValues(request) {
      request.success({ randomValues: nodeCrypto.randomBytes(request.length) });
    },
    request(request) {
      next({
        url: request.url, method: request.method, data: request.data,
        headers: request.header, timeoutMs: request.timeout
      }).then(request.success, request.fail);
    }
  };
  try {
    const { callApi } = require('../../utils/api');
    const data = { name: '演示用户' };
    const result = await callApi('bidirectional', data);
    assert.deepEqual(result.requestPlain, data);
    assert.deepEqual(result.responsePlain, { code: '0', message: null, data });
    assert.ok(result.requestCipher.encryptedDataBase64);
    assert.ok(result.responseCipher.encryptedDataBase64);
    assert.ok(result.latency.total >= 0);
    assert.equal(Object.hasOwn(result, 'sessionKey'), false);
    assert.ok(requests.every((request) => request.url.startsWith('https://')));
    const plain = await callApi('plain', data);
    assert.deepEqual(plain.requestPlain, data);
    assert.equal(plain.requestCipher, null);
    assert.deepEqual(plain.responsePlain, { code: '0', message: null, data });
    assert.equal(plain.responseCipher, null);
    global.wx.request = (request) => {
      request.success({ statusCode: 500, data: { status: 500, message: 'demo error' } });
    };
    await assert.rejects(callApi('plain', data), (error) => {
      assert.equal(error.code, 'HTTP_ERROR');
      assert.deepEqual(error.result.requestPlain, data);
      assert.equal(error.result.requestCipher, null);
      assert.equal(error.result.responseCipher, null);
      assert.deepEqual(error.result.responsePlain, { status: 500, message: 'demo error' });
      assert.ok(error.result.latency.total >= 0);
      return true;
    });
  } finally {
    if (previousWx === undefined) {
      delete global.wx;
    } else {
      global.wx = previousWx;
    }
  }
});

test('WeChat adapter preserves transport options and normalizes cross-realm random bytes', async () => {
  const crossRealm = vm.runInNewContext('new Uint8Array([10, 20, 30, 40]).buffer');
  const adapter = createWechatAdapter({
    request(request) {
      assert.equal(request.timeout, 1234);
      assert.deepEqual(request.header, { Authorization: 'token' });
      request.success({ statusCode: 400, data: { code: 'error' } });
    },
    getRandomValues(request) {
      request.success({ randomValues: crossRealm });
    }
  });
  assert.equal((await adapter.transport({
    url: 'https://kong.example.com', method: 'POST', data: {}, timeoutMs: 1234,
    headers: { Authorization: 'token' }
  })).statusCode, 400);
  assert.deepEqual(await adapter.randomBytes(4), new Uint8Array([10, 20, 30, 40]));
  const viewAdapter = createWechatAdapter({
    request() {},
    getRandomValues(request) {
      request.success({ randomValues: new DataView(crossRealm, 1, 2) });
    }
  });
  assert.deepEqual(await viewAdapter.randomBytes(2), new Uint8Array([20, 30]));
});

test('WeChat adapter random and network failures expose codes and causes', async () => {
  const cause = { errMsg: 'failed' };
  const adapter = createWechatAdapter({
    request(request) { request.fail(cause); },
    getRandomValues(request) { request.fail(cause); }
  });
  await assert.rejects(adapter.randomBytes(32), { code: 'RANDOM_UNAVAILABLE', cause });
  await assert.rejects(adapter.transport({}), { code: 'NETWORK_ERROR', cause });
  await assert.rejects(createWechatAdapter({ request() {} }).randomBytes(32),
    { code: 'RANDOM_UNAVAILABLE' });
  const invalid = createWechatAdapter({
    request() {},
    getRandomValues(request) { request.success({ randomValues: { byteLength: 32 } }); }
  });
  await assert.rejects(invalid.randomBytes(32), { code: 'RANDOM_UNAVAILABLE' });
  assert.throws(() => createWechatClient({ baseUrl: 'https://kong.example.com', platform: {} }),
    (error) => error instanceof SdkError && error.code === 'INVALID_ARGUMENT');
});
