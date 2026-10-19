# EncryptPii WeChat SDK

Instance-based client for the Spring server SDK or Kong crypto gateway.
**Application-layer encryption is disabled by default.** The core has no `wx` dependency; the WeChat adapter
uses `wx.request` and `wx.getRandomValues`. Importing the package does not start
network requests, fetch randomness, or replace Forge's random functions.

## Behavior at a glance

| Setting | Responsibility |
| --- | --- |
| Client `crypto.enabled` | Allows encrypted modes; defaults to `false`, captured at client creation |
| Request `mode` | Selects the client's encryption directions; must match the endpoint |
| SDK-owned `X-STC-Enabled` | Declares whether this business request actually uses crypto |
| Spring annotations / Kong route flags | Decide server-side encryption directions when the request opts in |

Missing `X-STC-Enabled` means `false`. This allows plain and encrypted requests
on the same annotated Spring endpoint or configured Kong route, provided the
deployed server supports the current protocol. **Annotations do not enforce
mandatory encryption.** HTTPS, authentication and authorization remain required.

## WeChat integration

Publish this directory to your team's private npm registry, then install
`@encryptpii/wechat-sdk` in the mini program and run **Tools > Build npm** in
WeChat Developer Tools. Use a real AppID and register the service HTTPS origin in
the mini program's request domain allowlist.

```js
const { createWechatClient } = require('@encryptpii/wechat-sdk');

const client = createWechatClient({
  baseUrl: 'https://api.example.com',
  publicKeyPath: '/your-public-key-path',
  crypto: { enabled: true },
  timeoutMs: 15000,
  headers: { Authorization: 'Bearer <application-token>' }
});

async function send(data) {
  return client.send({ mode: 'bidirectional', endpoint: '/your-resource-path', data });
}
```

The example explicitly opts in. The server must already have crypto capability
enabled and the endpoint must support bidirectional encryption. For the Spring
SDK, configure `sensitive.transport.crypto.enabled=true` and annotate the
endpoint with both `@DecryptRequest` and `@EncryptResponse`.
For Kong, enable both `decrypt_request` and `encrypt_response` on the route.

To use plaintext, omit `crypto` or set `crypto: { enabled: false }`. Even if a
request still specifies `bidirectional`, the disabled switch forces plain
transport without changing its endpoint. A request with `mode: 'plain'` remains
plain even on a crypto-enabled client:

```js
await client.send({
  mode: 'plain',
  endpoint: '/your-plain-resource-path',
  data: { message: 'hello' }
});
```

Catch `SdkError` at the application boundary and map `error.code` to localized
messages. Do not log `data` or `cause` by default.

Keep a client per service origin/authentication context. The public key and parsed
RSA key caches are instance-local. No session key is persisted or returned.
Request-specific authentication headers can also be passed to `send`.
Header names are checked case-insensitively: callers cannot override
`X-STC-Enabled`, `X-STC-Key-Id` or `X-STC-Session-Key`.

### Multiple teams and services

Keep service registration in the application, not in this SDK. The demo provides
[`utils/client-factory.js`](../utils/client-factory.js) and
[`utils/clients.js`](../utils/clients.js): configure `SERVICES` by service ID,
then obtain clients with `getClient(service)`. Each service gets a distinct
instance even when services share an origin, isolating public-key caches and
crypto settings. Team-owned API modules fix the endpoint and mode and pass
current authentication headers on each call.

The factory snapshots configuration and creates clients lazily. `clear(service)`
or `clearAll()` removes cached instances for subsequent calls without cancelling
in-flight requests. Changed service configuration requires a new factory; clearing
an instance does not change its settings. Use separate factories for independent
environments or simultaneous authentication/tenant contexts.
The factory is an application helper, not an export of the published SDK.
See the [demo integration guide](../README.md#多-team-服务接入) for configuration
and lifecycle examples.

### Key refresh and platform requirements

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

### Client switch and per-request mode

Application-layer encryption is **disabled by default**. Set
`crypto: { enabled: true }` when creating either client to enable the encryption
behavior selected by each request's `mode`. With the option omitted, an empty
`crypto` object, or `enabled: false`, **all four modes use plain transport**:
the SDK does not fetch public keys, acquire randomness, send STC key headers, or
decrypt responses. JSON and URL-encoded form serialization remain unchanged.
The flag must be a boolean when supplied; strings such as `"true"` are rejected.

The SDK captures this setting when the client is created. Create another client
to change it; mutating the options object does not affect current or future
requests on an existing client. Request-level `mode` cannot override a disabled
switch. Encryption failures never cause automatic plaintext fallback.

Disabling encryption does not change `endpoint` or relax HTTPS requirements.
The Header is a request declaration, not capability discovery or a remote
switch. The SDK does not fetch server policy or automatically synchronize its
switch with the server.

With `crypto.enabled: true`, the modes behave as follows. Request bodies are JSON
by default; URL-encoded forms are also supported by the client:

| Mode | Request | Response | `X-STC-Enabled` |
| --- | --- | --- | --- |
| `plain` | JSON by default; optional URL-encoded form | JSON | `false` |
| `bidirectional` | Encrypted JSON by default; optional encrypted URL-encoded form + session-key headers | Decrypted JSON | `true` |
| `request-only` | Encrypted JSON by default; optional encrypted URL-encoded form + session-key headers | JSON | `true` |
| `response-only` | JSON by default; optional URL-encoded form + session-key headers | Decrypted JSON | `true` |

For Spring endpoints, `request-only` maps to `@DecryptRequest`, `response-only`
to `@EncryptResponse`, and `bidirectional` to both. The enable Header carries
no direction information and does not negotiate or validate this mapping for
the client. Agree on the mode with the service owner before calling an endpoint.

Every business POST sends `X-STC-Enabled` as the string `true` iff its effective
mode encrypts the request or decrypts the response, otherwise `false`. Thus
`plain` always sends `false`, even with the global crypto switch enabled; with
the switch disabled all four modes send `false`. Public-key GET requests omit
this flag. `X-STC-Enabled`, `X-STC-Key-Id` and `X-STC-Session-Key` are SDK-owned,
reserved case-insensitively: setting them in client or per-request `headers`
fails with `INVALID_ARGUMENT` before any network request.

The four modes select encryption behavior, not a business operation. JSON is
the default for each mode; `contentType` can select URL-encoded form requests.
Supply `endpoint` on each call; multiple endpoints can use the same mode.
Application-specific requests and error scenarios belong in the application,
not the SDK.

### Sending JSON and forms

`client.send({ mode, endpoint, data, headers?, contentType? })` returns the server's
`{ code, message, data }` result envelope. The business payload is in `data`.
This result shape is required by the client SDK, not by the Java encryption SDK.
JSON is the default request content type; `data` must be JSON serializable and is
snapshotted before asynchronous work.

Set `contentType` to `application/x-www-form-urlencoded` to submit a flat object
of string, finite number or boolean fields. Nested objects, arrays, null and
undefined values are rejected; repeated fields and multipart are unsupported.
For an effective plain or response-only request, the URL-encoded body is sent
unchanged. For request encryption, the SDK encrypts its encoded UTF-8 bytes and
sends `ivBase64` and `encryptedDataBase64` as URL-encoded fields.

Example encrypted form request:

```js
client.send({
  mode: 'request-only',
  endpoint: '/crypto/server/form-urlencoded',
  contentType: 'application/x-www-form-urlencoded',
  data: { name: 'Alice Smith', phone: '123+456' }
});
```

The form example requires `crypto.enabled: true` and a Spring endpoint with
`@DecryptRequest`. The current Kong plugin expects encrypted request envelopes
in JSON; do not use encrypted form bodies with that plugin.

### Opt-in diagnostics

`client.sendDetailed(...)` is explicitly opt-in and returns
the effective-mode flags, response data, ciphertext and timings for demos:

| Field | Meaning |
| --- | --- |
| `data` | Same business result envelope as `send()` |
| `encryptRequest`, `decryptResponse` | Effective mode flags, both `false` when crypto is disabled |
| `cipherRequest`, `cipherResponse` | Sent/received ciphertext when applicable, otherwise `null` |
| `requestHeaders` | Content type, enable flag and STC key headers; excludes application credentials |
| `responseHeaders` | Received response headers, with the content type normalized when available |
| `stcHeaders` | Only the two key headers, or `null` in effective plain mode |
| `timings` | `total`, `encryption`, `http` and `decryption`, in milliseconds |

`requestHeaders` includes `Content-Type`, `X-STC-Enabled` and any STC key headers,
but omits application credentials. No plaintext request
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

### Custom transports and adapters

`createClient({ baseUrl, publicKeyPath, transport, randomBytes, crypto?, timeoutMs?, headers? })` supports
existing network stacks and future platform adapters:

- `publicKeyPath` is required even for a plaintext-only client, but is not fetched
  until needed by an encrypted mode. `endpoint` and a valid `mode` are required on
  every `send` or `sendDetailed` call. Paths must start with a single `/` and cannot contain
  whitespace, backslashes, query strings or fragments. Invalid paths or unknown
  modes fail with `INVALID_ARGUMENT` before any network request.
  No business routing table is stored in the SDK.
- `transport({ url, method, data, timeoutMs, headers })` resolves to
  `{ statusCode, data, headers? }`, including for non-2xx responses. The runtime
  also accepts WeChat's `header` field. Preserve response headers so the client
  can distinguish encrypted responses from plaintext protocol errors. Return decoded JSON
  bodies. Reject only on network errors. Do not retry POST requests or follow
  redirects to another origin.
- `randomBytes(length)` is required by `createClient` and returns a promise of
  exactly `length` secure random bytes as `Uint8Array`. It is not called in
  effective plain mode. Never use `Math.random`.
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

All encrypted modes send `X-STC-Enabled: true` plus `X-STC-Key-Id` and
`X-STC-Session-Key`. The latter carries the RSA-wrapped AES session key, never
the plaintext key. Encrypted JSON request and response bodies contain only:

```json
{
  "ivBase64": "<12-byte IV, Base64>",
  "encryptedDataBase64": "<AES-GCM ciphertext followed by its tag, Base64>"
}
```

Do not put key metadata or the wrapped session key in the body. Plain and
response-only request bodies retain the business payload.

The server rejects invalid or duplicate enable flags, key headers without an
explicit `true`, and missing/duplicate/blank key headers when enabled. Spring
also rejects `true` when its crypto capability is off or the endpoint has no
crypto annotations. These are plaintext HTTP 400 protocol errors, not reasons
to retry using plaintext.

For modes that decrypt responses, `X-STC-Encrypted: true` selects decryption;
`false` selects plaintext processing. If the header is absent, the SDK also
recognizes a cipher envelope. HTTP status alone never determines encryption:
business errors may be encrypted and protocol errors may be plaintext. Effective
plain mode never attempts response decryption, even if ciphertext is returned.

Only HTTP 400 with `code: "KEY_EXPIRED"` and a valid replacement key permits one
retry, with fresh session material. Network failures, other HTTP errors and
authentication failures never trigger automatic replay. Public key fetches are
deduplicated per instance; failed fetches can be retried by a subsequent call.

`SdkError` exposes a stable `code` and optional `cause`. `HttpError` additionally
exposes `statusCode` and `data`; its message deliberately excludes response
bodies. Applications are responsible for localized messages and safe logging.
Codes are defined in `index.d.ts`.

## Rollout and migration

This protocol is incompatible with older encrypted clients that send key headers
without `X-STC-Enabled: true`. Upgrading a server does not infer opt-in from the
presence of key headers.

1. Coordinate the client/server upgrade; retain an isolated legacy-protocol
   endpoint while old encrypted clients remain active.
2. Enable crypto capability on all new server instances before enabling the
   new client. The new server can accept plaintext during client rollout.
3. To switch client behavior, create a new instance and use it for subsequent
   requests; let in-flight requests complete with their original instance.
4. Before disabling server capability, stop encrypted traffic and allow old
   clients and in-flight requests to drain. Otherwise those requests are rejected.

Existing SDK integrations must add `crypto: { enabled: true }` to retain
encrypted behavior. Merely keeping `mode: 'bidirectional'` is not enough.
There is no remote policy endpoint or automatic runtime switch in this SDK.

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

## Related documentation

- [Spring server SDK](../../sdk/README.md): enablement, annotations, Vault and errors
- [WeChat demo](../README.md): local setup and application routes
- [Kong gateway](../../kong/README.md): route flags and deployment
