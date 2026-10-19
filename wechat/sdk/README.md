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
  publicKeyPath: '/your-public-key-path',
  timeoutMs: 15000,
  headers: { Authorization: 'Bearer <application-token>' }
});

async function send(data) {
  return client.send({ mode: 'bidirectional', endpoint: '/your-resource-path', data });
}
```

Catch `SdkError` at the application boundary and map `error.code` to localized
messages. Do not log `data` or `cause` by default.

Keep a client per Kong origin/authentication context. The public key and parsed
RSA key caches are instance-local. No session key is persisted or returned.
Request-specific authentication headers can also be passed to `send`.
Header names are checked case-insensitively: callers cannot override
`X-STC-Key-Id` or `X-STC-Session-Key`.

The server returns `refreshAtEpochMillis` with each public key. The client uses
that timestamp to refresh its cached key on the next encrypted request. It does
not start a background timer or require a client-side timing setting.
`refreshAtEpochMillis` is calculated by the server from the key expiry and its
configured rotation window.

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

`client.send({ mode, endpoint, data, headers?, contentType? })` returns the server's
`{ code, message, data }` result envelope. The business payload is in `data`.
JSON is the default request content type; `data` must be JSON serializable and is
snapshotted before asynchronous work. Set `contentType` to
`application/x-www-form-urlencoded` to submit a flat object of string, number or
boolean fields as URL-encoded form data. The encoded UTF-8 bytes are encrypted;
the encrypted request body carries `ivBase64` and `encryptedDataBase64` as
URL-encoded fields with the selected form content type. Nested objects, arrays,
null and undefined form values are rejected. Repeated form fields and multipart
requests are not supported.

| Mode | Request | Response |
| --- | --- | --- |
| `plain` | JSON by default; optional URL-encoded form | JSON |
| `bidirectional` | Encrypted JSON by default; optional encrypted URL-encoded form + session-key headers | Decrypted JSON |
| `request-only` | Encrypted JSON by default; optional encrypted URL-encoded form + session-key headers | JSON |
| `response-only` | JSON by default; optional URL-encoded form + session-key headers | Decrypted JSON |

The four modes select encryption behavior, not a business operation. JSON is
the default for each mode; `contentType` can select URL-encoded form requests.
Supply `endpoint` on each call; multiple endpoints can use the same mode.
Application-specific requests and error scenarios belong in the application,
not the SDK.

Example encrypted form request:

```js
client.send({
  mode: 'request-only',
  endpoint: '/crypto/server/form-urlencoded',
  contentType: 'application/x-www-form-urlencoded',
  data: { name: 'Alice Smith', phone: '123+456' }
});
```

For encrypted modes, `X-STC-Key-Id` and `X-STC-Session-Key` are the only
transport for key metadata and the RSA-wrapped AES session key. Encrypted
request bodies contain only `ivBase64` and `encryptedDataBase64`; Kong rejects
the old body-key protocol.

`client.sendDetailed(...)` is explicitly opt-in and returns
`{ data, cipherRequest, cipherResponse, requestHeaders, stcHeaders, timings }` for demos;
`requestHeaders` includes `Content-Type` and STC headers but omits application
credentials. `data` contains the same result envelope as `send()`. No plaintext request
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

`createClient({ baseUrl, publicKeyPath, transport, randomBytes, timeoutMs?, headers? })` supports
existing network stacks and future platform adapters:

- `publicKeyPath` is required client configuration; `endpoint` is required on
  every `send` or `sendDetailed` call. Paths must start with a single `/` and cannot contain
  whitespace, backslashes, query strings or fragments. Invalid paths or unknown
  modes fail with `INVALID_ARGUMENT` before any network request.
  No business routing table is stored in the SDK.
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
Protocol constants and mode encryption flags live in `core/protocol.js`;
service routing is supplied by the application.

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

The package is currently version `0.1.0`. Consumers must now explicitly supply
`publicKeyPath` when creating a client and `endpoint` on each send call, and use
`bidirectional` for two-way encryption. Public API and wire-format changes must
be versioned and coordinated with consumers; breaking changes require a major
version after reaching `1.0.0`. Before production rollout, exercise all modes
against the deployed Kong/Java services and verify the WeChat npm build on a
device.
