# Sensitive Transport Crypto Kong Plugin

This plugin implements the EncryptPii SDK's hybrid RSA/AES-GCM wire format at Kong:

- Request-body mode decrypts `CipherRequestPayload` before forwarding the plain JSON body.
- Header mode decrypts `X-STC-SESSION-KEY` for response-only encryption.
- Responses are optionally encrypted with the per-request AES key.
- RSA private keys are loaded by `keyId` from their version in Vault KV v2, matching the SDK key ring's `<keyAlias>:<version>` format.
- The public-key endpoint is served by Kong, which reads the active public key and version metadata directly from Vault KV v2.

It requires Kong Gateway 3.x with LuaJIT and `lua-resty-openssl` installed in the Kong runtime.

目录结构：`k8s/` 存放 Kubernetes 清单，`plugins/sensitive-transport-crypto/` 存放 Lua 插件源码，`scripts/` 存放构建、部署、删除及路由配置脚本；`Dockerfile` 和旧版 `docker-compose.yml` 位于本目录。所有脚本继续读取仓库根目录 `.env`。

推荐部署到 Kubernetes：先部署 Vault 和 Server，再执行 `./kong/scripts/deploy-to-k8s.sh`，最后部署 Client。Kong 默认通过集群内 Service 访问 Server/Vault，并使用绑定到 `kong/encryptpii-kong` ServiceAccount 的 Vault Kubernetes auth role；Vault token 不存储在 Kubernetes Secret 中。

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
- `../vault/scripts/rotate-vault-key.sh` creates a new RSA-2048 key version at a specified existing Vault KV v2 secret, preserving other fields and all historical versions. It uses CAS to reject competing updates rather than overwriting them.

明文演示使用独立 Service `encryptpii-server-plain`：Kong POST `/plain/server/normal` 保留路径透传至 Server `/plain/server/normal`（`strip_path:false`），不挂载任何插件。Client 仅保留 `/plain/client/normal` 明文入口，不获取公钥、不加解密；目标 URL 从 `application.yml` 的 `plain.server.endpoints.normal` 读取，为 `/plain/server/normal`，加密目标由 `crypto.server` 独立配置。Kubernetes 部署和 Admin API 配置脚本均安装这条独立路由，原有加密路由保持不变。不要将加密插件配置为全局或绑定到明文 Service，否则它仍会作用于该链路。明文链路仅用于本地演示。

Manual key rotation from the host:

```bash
./vault/scripts/rotate-vault-key.sh --dry-run secret/data/sensitive-transport-crypto/rsa-ciam
./vault/scripts/rotate-vault-key.sh secret/data/sensitive-transport-crypto/rsa-ciam
```

Rotation defaults to `kubectl exec` against Kubernetes Vault in the `docker-desktop` context, using `vault/.local/rotation-token` (or explicit `VAULT_TOKEN`), without port forwarding. For external Vault, add `--http`; the HTTP-specific settings below apply only in that mode.

The script reads the repository-root `.env`; `VAULT_ADDR` and `VAULT_TOKEN` override its Vault settings. When using the `.env` address, the rotation script maps `host.docker.internal` to `localhost` for execution on the host, preserving the scheme, port, and path. An explicit `VAULT_ADDR` is used unchanged; Kong's configuration is not modified. The path argument is optional when `ENCRYPTPII_VAULT_SECRET_PATH` is set. Use a dedicated rotation token with `read` and `update` permissions on the target data path; Kong's Kubernetes auth role remains read-only. Keys are stored as Base64 X.509 public-key DER and PKCS#8 private-key DER, matching the SDK. Temporary secret files have restrictive permissions and are removed on exit; no key or token is printed. This is a one-time rotation, not an automatic scheduler. If CAS fails, inspect the latest version before running again.

Legacy Docker Compose installation (not the default Kubernetes workflow; requires a Vault token):

```bash
cp .env.example .env
# Set ENCRYPTPII_VAULT_TOKEN and KONG_TO_ENCRYPTPII_AUTH_TOKEN in the root .env.
./kong/scripts/install-to-kong.sh
```

To rebuild the plugin image only, run `./scripts/build-plugin.sh`. To reapply route configuration without restarting Kong, run `./scripts/configure-routes.sh`.

The plugin scripts `build-plugin.sh`, `install-to-kong.sh`, and `configure-routes.sh` share `load-env.sh` to read settings from the repository-root `.env`, regardless of the current working directory. The Vault rotation script lives in `vault/scripts/rotate-vault-key.sh` and reads that same root `.env` through the shared loader. Exported environment variables take precedence over `.env`; required settings must be nonempty. Use literal `KEY=value` assignments, optionally surrounded by single or double quotes; shell commands and variable interpolation are not evaluated. The build and install scripts explicitly pass the root `.env` to Docker Compose. Changing route settings requires rerunning `configure-routes.sh`; for Kubernetes, redeploy Server followed by Kong after changing the shared auth token. For legacy Compose, restart/reinstall Kong and restart the host-run Server after changing it.

The legacy installer requires Docker Compose, `curl`, `jq`, and Bash. The Compose setup uses Kong 3.7; pin and test the matching base image for other environments. The root `.env` now uses Kubernetes addresses. To use the legacy host-based setup, explicitly override `ENCRYPTPII_UPSTREAM_URL=http://host.docker.internal:9090` and `ENCRYPTPII_VAULT_ADDR=http://host.docker.internal:8200`, and provide the corresponding tokens. This installer is not used for Kubernetes deployments.

The script configures Kong only. The Spring server must also be started with `KONG_TO_ENCRYPTPII_AUTH_TOKEN` set to the same value used by Kong; otherwise its protected plaintext endpoints reject requests.

## Configure

Configure the plugin only on protected routes. Give Kong's Vault auth role read-only access to the SDK's KV v2 path. The plugin reads `privateKey` by the version embedded in the request's `keyId`; it does not store private keys in Kong's database. Restrict access to the Admin API.

Example declarative configuration (replace placeholders through your secrets system):

```yaml
plugins:
  - name: sensitive-transport-crypto
    route: encrypted-api
    config:
      vault_addr: http://host.docker.internal:8200
      vault_token: "{vault://env/ENCRYPTPII_VAULT_TOKEN}"
      vault_secret_path: secret/data/sensitive-transport-crypto/rsa-ciam
      key_alias: rsa-ciam
      key_validity_millis: 60000
      key_grace_period_millis: 30000
      upstream_path: /crypto/server/bidirectional
      upstream_auth_token: "{vault://env/KONG_TO_ENCRYPTPII_AUTH_TOKEN}"
      decrypt_request: true
      encrypt_response: true
      max_body_bytes: 1048576
```

Use `decrypt_request: true, encrypt_response: false` for request-only encryption. Response-only routes set `decrypt_request: false, encrypt_response: true, session_key_source: header`.

The `/crypto/server/public-key` route is handled directly by the plugin: Kong reads the latest KV v2 version and returns the SDK-compatible `publicKeyBase64`, `keyId`, and `expiresAtEpochMillis` response without proxying to Spring. Protected business requests are decrypted and forwarded to Server `/crypto/server/*`; those handlers accept plaintext only when the configured `X-Crypto-Gateway-Token` matches.

The local Kong instance is configured with these routes:

| Client path | Method | Upstream path | Crypto behavior |
| --- | --- | --- | --- |
| `/crypto/server/public-key` | GET | none | Kong reads active public key and metadata from Vault |
| `/crypto/server/bidirectional` | POST | `/crypto/server/bidirectional` | Decrypt request and encrypt response |
| `/crypto/server/request-only` | POST | `/crypto/server/request-only` | Decrypt request |
| `/crypto/server/response-only` | POST | `/crypto/server/response-only` | Decrypt session-key headers and encrypt response |

For Kubernetes, grant the bound auth role only `read` access to `secret/data/sensitive-transport-crypto/rsa-ciam` and `secret/metadata/sensitive-transport-crypto/rsa-ciam`. For the legacy Compose workflow, configure a non-root Vault token and a random gateway token through your secret manager.

Use brace-wrapped Kong secret references exactly as shown. Configure `KONG_TO_ENCRYPTPII_AUTH_TOKEN` with the same random secret for the Spring server and Kong. The server rejects internal plaintext routes if the token is unset or incorrect. Do not expose those internal routes directly to untrusted networks.

## Operational limits

- Kong buffers request bodies for decryption and buffers upstream response chunks before encryption. `max_body_bytes` applies to both, defaults to 1 MiB, and is capped at 16 MiB; the Compose setup also caps Nginx request bodies at 16 MiB to bound buffering.
- The plugin asks the upstream for identity encoding and clears response compression headers before transforming the response.
- All routes using this plugin must use HTTPS between the client and Kong, and TLS should also be used to Vault when deployed outside this local demo. The plugin sees decrypted request and response data; exclude those bodies from logs, tracing, and diagnostics.
- Invalid encrypted requests receive HTTP 400, oversized bodies receive HTTP 413, and response encryption failures receive HTTP 502.
- Keep the SDK's key alias and Vault secret path identical in Kong and the Spring server. The plugin fetches exact KV v2 versions, so old versions must remain readable throughout the grace window.
