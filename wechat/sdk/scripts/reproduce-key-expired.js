const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const { createWechatClient } = require('../index');

function makeKey(keyId) {
  const pair = nodeCrypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    info: {
      keyId,
      publicKeyBase64: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
      expiresAtEpochMillis: Date.now() + 600000,
      refreshAtEpochMillis: Date.now() + 300000
    }
  };
}

function createScenarioPlatform(initialKey, replacementKey) {
  const stats = {
    publicKeyGets: 0,
    encryptedPosts: 0,
    requestKeyIds: []
  };

  function respond(request, response) {
    if (typeof request.success === 'function') {
      request.success(response);
    }
  }

  return {
    stats,
    platform: {
      getRandomValues(request) {
        respond(request, { randomValues: nodeCrypto.randomBytes(request.length) });
      },
      request(request) {
        queueMicrotask(() => {
          if (request.method === 'GET' && request.url.endsWith('/crypto/server/public-key')) {
            stats.publicKeyGets += 1;
            respond(request, {
              statusCode: 200,
              data: initialKey.info,
              header: { 'X-STC-Encrypted': 'false', 'Cache-Control': 'no-store' }
            });
            return;
          }

          if (request.method === 'POST' && request.url.endsWith('/crypto/server/response-only')) {
            stats.encryptedPosts += 1;
            stats.requestKeyIds.push(request.header['X-STC-Key-Id']);
            if (stats.encryptedPosts === 1) {
              respond(request, {
                statusCode: 400,
                data: {
                  code: 'KEY_EXPIRED',
                  message: 'stale test key',
                  data: replacementKey.info
                },
                header: { 'X-STC-Encrypted': 'false', 'Cache-Control': 'no-store' }
              });
              return;
            }
            respond(request, {
              statusCode: 200,
              data: {
                code: '0',
                message: null,
                data: {
                  scenario: 'KEY_EXPIRED',
                  recoveredWithKeyId: request.header['X-STC-Key-Id']
                }
              },
              header: { 'X-STC-Encrypted': 'false' }
            });
            return;
          }

          if (typeof request.fail === 'function') {
            request.fail(new Error(`Unexpected request: ${request.method} ${request.url}`));
          }
        });
      }
    }
  };
}

async function runScenario() {
  const initialKey = makeKey('stale-key');
  const replacementKey = makeKey('fresh-key');
  const { platform, stats } = createScenarioPlatform(initialKey, replacementKey);
  const client = createWechatClient({
    baseUrl: 'https://kong.example.com',
    platform
  });

  const result = await client.send({
    mode: 'response-only',
    data: { demo: 'force-key-expired' }
  });

  return {
    result,
    publicKeyGets: stats.publicKeyGets,
    encryptedPosts: stats.encryptedPosts,
    requestKeyIds: stats.requestKeyIds.slice(),
    initialKeyId: initialKey.info.keyId,
    replacementKeyId: replacementKey.info.keyId
  };
}

async function main() {
  const summary = await runScenario();
  assert.equal(summary.publicKeyGets, 1);
  assert.equal(summary.encryptedPosts, 2);
  assert.deepEqual(summary.requestKeyIds, [summary.initialKeyId, summary.replacementKeyId]);
  assert.deepEqual(summary.result, {
    code: '0',
    message: null,
    data: {
      scenario: 'KEY_EXPIRED',
      recoveredWithKeyId: summary.replacementKeyId
    }
  });

  console.log('KEY_EXPIRED reproduction completed.');
  console.log(JSON.stringify(summary, null, 2));
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}

module.exports = { runScenario };
