const test = require('node:test');
const assert = require('node:assert/strict');
const { runScenario } = require('../scripts/reproduce-key-expired');

test('local KEY_EXPIRED reproduction prints the retry log and retries with the replacement key', async () => {
  const originalLog = console.log;
  const logCalls = [];
  console.log = (...args) => {
    logCalls.push(args);
  };

  try {
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
    assert.ok(logCalls.some((args) => args[0] === 'Server key expired, attempting to install new key...'));
  } finally {
    console.log = originalLog;
  }
});

