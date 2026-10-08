# EncryptPii WeChat SDK

Instance-based Kong client. The core has no `wx` dependency; the WeChat adapter
uses `wx.request` and `wx.getRandomValues`. Importing the package does not start
network requests, fetch randomness, or replace Forge's random functions.

## WeChat integration

Publish this directory to your team's private npm registry, then install
`@encryptpii/wechat-sdk` in the mini program and run **Tools > Build npm** in
WeChat Developer Tools. Use a real AppID and register the Kong HTTPS origin in
the mini program's request domain allowlist.

```js
const { createWechatClient } = require('@encryptpii/wechat-sdk');

const client = createWechatClient({
  baseUrl: 'https://kong.example.com',
  timeoutMs: 15000,
  keyRefreshMarginMs: 1000,
  headers: { Authorization: 'Bearer <application-token>' }
});

async function send(data) {
  return client.send({ mode: 'bidirectional', data });
}
```

Catch `SdkError` at the application boundary and map `error.code` to localized
messages. Do not log `data` or `cause` by default.

Keep a client per Kong origin/authentication context. The public key and parsed
RSA key caches are instance-local. No session key is persisted or returned.
Request-specific authentication headers can also be passed to `send`.
Header names are checked case-insensitively: callers cannot override
`X-STC-Key-Id` or `X-STC-Session-Key`.

`keyRefreshMarginMs` controls how long before `expiresAtEpochMillis` a cached key
is considered stale. The next encrypted request fetches a replacement on demand;
it does not start a background timer. It defaults to 1000 ms and can be set to 0
to use the cache until its expiry.

The minimum supported WeChat base library is **3.4.10** (the demo's configured
baseline). A runtime without `wx.getRandomValues` can still send plain requests;
encrypted requests fail with `RANDOM_UNAVAILABLE`, without an insecure fallback.
Validate deployment on real devices as well as the simulator.

HTTPS is required for remote services. For local development, HTTP origins whose
host is `localhost`, `127.0.0.1` or `[::1]` are accepted without an extra option.
Remote HTTP addresses remain rejected. In WeChat Developer
Tools, also disable domain/TLS/HTTPS certificate validation for this local setup.
This does not bypass WeChat's network rules, and localhost on a real device
refers to the device itself. Use a reachable HTTPS origin for device testing and
production.

## API

`client.send({ mode, data, headers? })` returns the server's
`{ code, message, data }` result envelope. The business payload is in `data`.
`data` must be JSON serializable. It is snapshotted before asynchronous work.

| Mode | Request | Response |
| --- | --- | --- |
| `plain` | JSON | JSON |
| `bidirectional` | Encrypted JSON + session-key headers | Decrypted JSON |
| `request-only` | Encrypted JSON + session-key headers | JSON |
| `response-only` | JSON + session-key headers | Decrypted JSON |
| `response-only/client-exception` | JSON + session-key headers | Decrypted HTTP 400 error |
| `response-only/system-exception` | JSON + session-key headers | Decrypted HTTP 500 error |
| `response-only/business-exception` | JSON + session-key headers | Decrypted HTTP 200 business error |

For encrypted modes, `X-STC-Key-Id` and `X-STC-Session-Key` are the only
transport for key metadata and the RSA-wrapped AES session key. Encrypted
request bodies contain only `ivBase64` and `encryptedDataBase64`; Kong rejects
the old body-key protocol.

`client.sendDetailed(...)` is explicitly opt-in and returns
`{ data, cipherRequest, cipherResponse, stcHeaders, timings }` for demos; `data` contains the
same result envelope as `send()`. No plaintext request
or session key is included. The business response can still contain sensitive
information, so do not log this result in production. `total` includes key
acquisition and retries; the other timings describe the successful attempt,
and `encryption` includes asynchronous random acquisition.

HTTP failures still reject, but `sendDetailed()` attaches the final attempt's
diagnostics as `error.details`. Its `data` contains the error body, decrypted
when encrypted; plaintext gateway errors are returned unchanged. Error bodies
need not use the business result envelope. Decryption failures also expose
diagnostics, with `data: null` and the received ciphertext, and remain errors.
These diagnostics may contain sensitive data and must not be logged by default.

`createClient({ baseUrl, transport, randomBytes, timeoutMs?, keyRefreshMarginMs?, headers? })` supports
existing network stacks and future platform adapters:

- `transport({ url, method, data, timeoutMs, headers })` resolves to
  `{ statusCode, data }`, including for non-2xx responses. Return decoded JSON
  bodies. Reject only on network errors. Do not retry POST requests or follow
  redirects to another origin.
- `randomBytes(length)` returns a promise of exactly `length` secure random bytes
  as `Uint8Array`. Never use `Math.random`.
- `createWechatAdapter(platform)` returns these two functions for injection.
  `createWechatClient` uses the global `wx` by default or an explicit `platform`.

The core currently uses synchronous Forge cryptographic operations after random
acquisition. A Web/Node adapter can reuse the protocol, but a native/WebCrypto
backend would require a separate implementation with the same wire format.

## Protocol and failures

The package preserves the Java/Kong protocol: RSA-OAEP SHA-256 with MGF1 SHA-1,
AES-256-GCM, a 12-byte IV and a 16-byte authentication tag appended to ciphertext.
The OAEP seed is supplied explicitly from the platform's secure random source.
Protocol fields and routing live in `core/protocol.js`.

Only HTTP 400 with `code: "KEY_EXPIRED"` and a valid replacement key permits one
retry, with fresh session material. Network failures, other HTTP errors and
authentication failures never trigger automatic replay. Public key fetches are
deduplicated per instance; failed fetches can be retried by a subsequent call.

`SdkError` exposes a stable `code` and optional `cause`. `HttpError` additionally
exposes `statusCode` and `data`; its message deliberately excludes response
bodies. Applications are responsible for localized messages and safe logging.
Codes are defined in `index.d.ts`.

## Packaging and maintenance

```sh
cd wechat/sdk
npm test
npm run test:java
npm pack --dry-run
npm publish --registry https://your-private-registry.example.com
```

The registry URL is a placeholder: configure your organization's actual
registry and permissions before publishing. `npm pack` includes only runtime
files, types and documentation, not tests or the demo. No install-time
dependencies are required: Forge is vendored in `lib/forge.min.js`, with its
original license in `lib/FORGE-LICENSE.txt`. Upgrade that bundle deliberately,
with protocol regression coverage; do not replace it with a platform-dependent
Node build.

`npm test` requires Node 18+ and checks all modes against independent Node RSA/AES
primitives, failures, concurrency and the WeChat adapter. `npm run test:java`
additionally requires JDK 17+ on PATH and checks a full round trip with the JCA
algorithms and default OAEP parameters used by the Java client.

The package is currently version `0.1.0`. Public API and wire-format changes must
be versioned and coordinated with consumers; breaking changes require a major
version after reaching `1.0.0`. Before production rollout, exercise all modes
against the deployed Kong/Java services and verify the WeChat npm build on a
device.
