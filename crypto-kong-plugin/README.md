# Sensitive Transport Crypto Kong Plugin

This plugin implements the EncryptPii SDK's hybrid RSA/AES-GCM wire format at Kong:

- Request-body mode decrypts `CipherRequestPayload` before forwarding the plain JSON body.
- Header mode decrypts `X-STC-SESSION-KEY` for response-only encryption.
- Responses are optionally encrypted with the per-request AES key.
- RSA private keys are loaded by `keyId` from their version in Vault KV v2, matching the SDK key ring's `<keyAlias>:<version>` format.
- The public-key endpoint is served by Kong, which reads the active public key and version metadata directly from Vault KV v2.

It requires Kong Gateway 3.x with LuaJIT and `lua-resty-openssl` installed in the Kong runtime.

## Cryptographic compatibility

The request payload format is:

```json
{
  "keyId": "ciam:1",
  "encryptedSessionKeyBase64": "<RSA-OAEP ciphertext>",
  "ivBase64": "<12-byte IV>",
  "encryptedDataBase64": "<AES-GCM ciphertext followed by the 16-byte tag>"
}
```

The RSA operation uses OAEP with SHA-256 and MGF1-SHA-1, matching the Java SDK's `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` default parameters. AES uses 256-bit GCM with a 12-byte IV and 128-bit tag. The response JSON has `ivBase64` and `encryptedDataBase64`, matching the SDK's `CipherResponsePayload`.

The plugin loads key versions directly from Vault and caches parsed keys for 60 seconds per Kong worker. For non-active keys, it enforces `created_time + key_validity_millis + key_grace_period_millis`; keep those values aligned with the Spring server and keep Vault versions available through the grace window.

## Build and install scripts

All scripts live under `scripts/`:

- `build-plugin.sh` builds `encryptpii-kong:3.7` and compiles both Lua files with the Kong image's LuaJIT.
- `configure-routes.sh` idempotently creates or updates the upstream service, public-key route, three business routes, and their route-scoped plugin configurations through the Kong Admin API.
- `install-to-kong.sh` checks local credentials, builds and starts Kong with the plugin enabled, waits for the Admin API, then configures the routes.

Local installation:

```bash
cd crypto-kong-plugin
cp .env.example .env
# Set ENCRYPTPII_VAULT_TOKEN and a random ENCRYPTPII_GATEWAY_TOKEN in .env.
./scripts/install-to-kong.sh
```

To rebuild the plugin image only, run `./scripts/build-plugin.sh`. To reapply route configuration without restarting Kong, run `./scripts/configure-routes.sh`.

The installer requires Docker Compose, `curl`, `jq`, and Bash. The local Compose setup uses Kong 3.7; pin and test the matching base image for other environments. It expects the Spring upstream at `http://host.docker.internal:9090` and Vault at `http://host.docker.internal:8200` by default. Override these with `ENCRYPTPII_UPSTREAM_URL`, `ENCRYPTPII_VAULT_ADDR`, `ENCRYPTPII_VAULT_SECRET_PATH`, `ENCRYPTPII_KEY_ALIAS`, and the lifecycle/body-limit variables documented in `configure-routes.sh`.

The script configures Kong only. The Spring server must also be started with `KONG_CRYPTO_GATEWAY_TOKEN` set to the same value as `ENCRYPTPII_GATEWAY_TOKEN`; otherwise its protected plaintext endpoints reject requests.

## Configure

Configure the plugin only on protected routes. Give the Kong token read-only access to the SDK's KV v2 path. The plugin reads `privateKey` by the version embedded in the request's `keyId`; it does not store private keys in Kong's database. Restrict access to the Admin API.

Example declarative configuration (replace placeholders through your secrets system):

```yaml
plugins:
  - name: crypto-kong-plugin
    route: encrypted-api
    config:
      vault_addr: http://host.docker.internal:8200
      vault_token: "{vault://env/ENCRYPTPII_VAULT_TOKEN}"
      vault_secret_path: secret/data/sensitive-transport-crypto/rsa-ciam
      key_alias: rsa-ciam
      key_validity_millis: 60000
      key_grace_period_millis: 30000
      upstream_path: /crypto/kong/bidirectional
      upstream_auth_token: "{vault://env/ENCRYPTPII_GATEWAY_TOKEN}"
      decrypt_request: true
      encrypt_response: true
      max_body_bytes: 1048576
```

Use `decrypt_request: true, encrypt_response: false` for request-only encryption. Response-only routes set `decrypt_request: false, encrypt_response: true, session_key_source: header`.

The `/crypto/server/public-key` route is handled directly by the plugin: Kong reads the latest KV v2 version and returns the SDK-compatible `publicKeyBase64`, `keyId`, and `expiresAtEpochMillis` response without proxying to Spring. The protected business routes are rewritten to `/crypto/kong/*`; those handlers accept plaintext only when the configured `X-Crypto-Gateway-Token` matches.

The local Kong instance is configured with these routes:

| Client path | Method | Upstream path | Crypto behavior |
| --- | --- | --- | --- |
| `/crypto/server/public-key` | GET | none | Kong reads active public key and metadata from Vault |
| `/crypto/server/bidirectional` | POST | `/crypto/kong/bidirectional` | Decrypt request and encrypt response |
| `/crypto/server/request-only` | POST | `/crypto/kong/request-only` | Decrypt request |
| `/crypto/server/response-only` | POST | `/crypto/kong/response-only` | Decrypt session-key headers and encrypt response |

For production, grant Kong only `read` access to `secret/data/sensitive-transport-crypto/rsa-ciam` and `secret/metadata/sensitive-transport-crypto/rsa-ciam`. Configure a non-root Vault token and a random gateway token through your secret manager.

Use brace-wrapped Kong secret references exactly as shown. Configure `KONG_CRYPTO_GATEWAY_TOKEN` for the Spring server and `ENCRYPTPII_GATEWAY_TOKEN` for Kong with the same random secret. The server rejects internal plaintext routes if the token is unset or incorrect. Do not expose those internal routes directly to untrusted networks.

## Operational limits

- Kong buffers request bodies for decryption and buffers upstream response chunks before encryption. `max_body_bytes` applies to both, defaults to 1 MiB, and is capped at 16 MiB; the Compose setup also caps Nginx request bodies at 16 MiB to bound buffering.
- The plugin asks the upstream for identity encoding and clears response compression headers before transforming the response.
- All routes using this plugin must use HTTPS between the client and Kong, and TLS should also be used to Vault when deployed outside this local demo. The plugin sees decrypted request and response data; exclude those bodies from logs, tracing, and diagnostics.
- Invalid encrypted requests receive HTTP 400, oversized bodies receive HTTP 413, and response encryption failures receive HTTP 502.
- Keep the SDK's key alias and Vault secret path identical in Kong and the Spring server. The plugin fetches exact KV v2 versions, so old versions must remain readable throughout the grace window.
