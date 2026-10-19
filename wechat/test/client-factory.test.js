const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const forge = require('../sdk/lib/forge.min');
const { createClientFactory } = require('../utils/client-factory');

const serviceOptions = {
  baseUrl: 'https://api.example.com',
  publicKeyPath: '/customer/public-key',
  crypto: { enabled: true }
};

test('factory creates lazily and caches by service rather than origin', () => {
  const created = [];
  const factory = createClientFactory({
    customer: serviceOptions,
    order: { ...serviceOptions, publicKeyPath: '/order/public-key' }
  }, (options) => {
    const client = { options };
    created.push(client);
    return client;
  });
  assert.equal(created.length, 0);
  const customer = factory.getClient('customer');
  assert.equal(factory.getClient('customer'), customer);
  const order = factory.getClient('order');
  assert.notEqual(customer, order);
  assert.equal(order.options.publicKeyPath, '/order/public-key');
  factory.clear('customer');
  assert.notEqual(factory.getClient('customer'), customer);
  assert.equal(factory.getClient('order'), order);
  factory.clearAll();
  assert.notEqual(factory.getClient('order'), order);
});

test('registry snapshots options and rejects unknown services without creating clients', () => {
  const config = {
    customer: { ...serviceOptions, crypto: { enabled: true }, headers: { 'X-App': 'original' } }
  };
  let created = 0;
  const factory = createClientFactory(config, (options) => { created += 1; return { options }; });
  config.customer.baseUrl = 'https://changed.example.com';
  config.customer.crypto.enabled = false;
  config.customer.headers['X-App'] = 'changed';
  for (const service of ['unknown', '__proto__', 'toString', '', null, undefined]) {
    assert.throws(() => factory.getClient(service), { code: 'INVALID_ARGUMENT' });
    assert.throws(() => factory.clear(service), { code: 'INVALID_ARGUMENT' });
  }
  assert.equal(created, 0);
  assert.deepEqual(factory.getClient('customer').options, {
    ...serviceOptions, headers: { 'X-App': 'original' }
  });
  assert.equal(created, 1);
});

test('failed client construction is not cached', () => {
  let attempts = 0;
  const factory = createClientFactory({ customer: serviceOptions }, () => {
    attempts += 1;
    if (attempts === 1) throw new Error('Platform unavailable');
    return {};
  });
  assert.throws(() => factory.getClient('customer'), /Platform unavailable/);
  assert.ok(factory.getClient('customer'));
  assert.equal(attempts, 2);
  for (const registry of [null, [], true, { customer: null }]) {
    assert.throws(() => createClientFactory(registry), { code: 'INVALID_ARGUMENT' });
  }
});

test('same-origin services isolate real public keys and forward fresh request authentication', async () => {
  const keys = {};
  const fetches = { customer: 0, order: 0 };
  const sessions = [];
  for (const service of Object.keys(fetches)) {
    const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    keys[service] = {
      nodePrivateKey: pair.privateKey,
      privateKey: forge.pki.privateKeyFromPem(pair.privateKey.export({ type: 'pkcs8', format: 'pem' })),
      info: {
        keyId: `${service}:1`,
        publicKeyBase64: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
        expiresAtEpochMillis: Date.now() + 600000,
        refreshAtEpochMillis: Date.now() + 300000
      }
    };
  }
  let token = 'first';
  const platform = {
    getRandomValues(request) {
      request.success({ randomValues: crypto.randomBytes(request.length) });
    },
    request(request) {
      try {
        const [, service] = new URL(request.url).pathname.split('/');
        const key = keys[service];
        assert.equal(request.header.authorization, token);
        if (request.method === 'GET') {
          fetches[service] += 1;
          request.success({ statusCode: 200, data: key.info });
          return;
        }
        assert.equal(request.header['X-STC-Key-Id'], key.info.keyId);
        assert.equal(request.header['X-STC-Enabled'], 'true');
        const block = crypto.privateDecrypt(
          { key: key.nodePrivateKey, padding: crypto.constants.RSA_NO_PADDING },
          Buffer.from(request.header['X-STC-Session-Key'], 'base64')
        );
        const session = forge.pkcs1.decode_rsa_oaep(key.privateKey, block.toString('binary'), {
            md: forge.md.sha256.create(), mgf1: { md: forge.md.sha1.create() }
          });
        sessions.push(Buffer.from(session, 'binary').toString('hex'));
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(session, 'binary'), iv);
        const ciphertext = Buffer.concat([
          cipher.update(JSON.stringify({ code: '0', message: null, data: service })),
          cipher.final(), cipher.getAuthTag()
        ]);
        request.success({
          statusCode: 200,
          header: { 'X-STC-Encrypted': 'true' },
          data: { ivBase64: iv.toString('base64'), encryptedDataBase64: ciphertext.toString('base64') }
        });
      } catch (error) {
        request.fail(error);
      }
    }
  };
  const factory = createClientFactory(Object.fromEntries(Object.keys(keys).map((service) => [
    service, { ...serviceOptions, publicKeyPath: `/${service}/public-key`, platform }
  ])));
  async function send(service) {
    const response = await factory.getClient(service).send({
      mode: 'response-only', endpoint: `/${service}/resource`, data: {},
      headers: { Authorization: token }
    });
    assert.equal(response.data, service);
  }
  await Promise.all([send('customer'), send('order')]);
  token = 'refreshed';
  await Promise.all([send('customer'), send('order')]);
  assert.deepEqual(fetches, { customer: 1, order: 1 });
  factory.clear('customer');
  await send('customer');
  assert.deepEqual(fetches, { customer: 2, order: 1 });
  assert.equal(new Set(sessions).size, 5);
});
