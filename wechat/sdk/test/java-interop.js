const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { createClient } = require('..');

test('SDK request decrypts in JCA and JCA response decrypts in SDK', async () => {
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privateKey = pair.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  const client = createClient({
    baseUrl: 'https://kong.example.com',
    randomBytes: async (length) => new Uint8Array(crypto.randomBytes(length)),
    transport: async (request) => {
      if (request.method === 'GET') {
        return {
          statusCode: 200,
          data: {
            keyId: 'java',
            publicKeyBase64: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
            expiresAtEpochMillis: Date.now() + 60000
          }
        };
      }
      const payload = request.data;
      const java = spawnSync('java', [path.join(__dirname, 'JavaInterop.java')], {
        input: [privateKey, payload.encryptedSessionKeyBase64, payload.ivBase64,
          payload.encryptedDataBase64, ''].join('\n'),
        encoding: 'utf8',
        timeout: 30000
      });
      if (java.error) throw java.error;
      assert.equal(java.status, 0, java.stderr);
      const lines = java.stdout.trim().split(/\r?\n/);
      assert.equal(lines.length, 2);
      return {
        statusCode: 200,
        data: { ivBase64: lines[0], encryptedDataBase64: lines[1] }
      };
    }
  });
  const data = { name: '测试用户', nested: { value: 'hello 🌍' } };
  assert.deepEqual(await client.send({ mode: 'bidirectional', data }), data);
});
