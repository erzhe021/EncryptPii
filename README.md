# EncryptPii

EncryptPii demonstrates application-level encryption of sensitive data using a Java client, a Lua Kong plugin, and HashiCorp Vault KV v2.
Kong handles public-key delivery, request decryption, and response encryption;
The Spring Boot business server handles plaintext and does not connect to Vault.

The current Gradle project contains `client` and `server` modules.

## Architecture

```text
Java demo client (8080)
  | public-key requests and encrypted business traffic
  v
Kong proxy (8000) ---- read public/private keys and metadata ----> Vault KV v2 (8200)
  | plaintext requests with X-Crypto-Gateway-Token
  v
Spring business server (9090)

rotate-vault-key.sh ---- generate RSA key pair / write new version ----> Vault
```

The client creates a new AES-256 session key for each business request and transports it using RSA-OAEP. Kong decrypts that session key using the Vault key version identified by `keyId`. For bidirectional and response-only requests, Kong uses the same AES session key to encrypt the upstream response.

This encryption is not a substitute for TLS. The demo client's inbound APIs accept plaintext, and Kong-to-server traffic is plaintext at the application layer.

## Project layout

```text
client/                         Spring Boot client demo and Java crypto helpers
server/                         Plaintext business endpoints protected by a gateway token
server/.env.example             Spring server token configuration template
sensitive-transport-crypto/
  .env.example                  Kong and Vault configuration template
  Dockerfile                    Kong 3.7 image containing the Lua plugin
  docker-compose.yml            Kong, PostgreSQL, and migration containers
  kong/plugins/
    sensitive-transport-crypto/  Plugin handler and schema
  scripts/                      Build, installation, route configuration, key rotation
  README.md                     Detailed plugin reference
```

## Quick start

### Prerequisites

- JDK 17 and the included Gradle wrapper.
- Docker with Docker Compose.
- Bash, `curl`, and `jq`; OpenSSL for the key rotation script.
- A running Vault with KV v2 enabled and an existing RSA key secret.

Vault is not started by the Kong Compose file. Ensure ports 5432, 8000, 8001, 8002, 8443, and 8444 are available for the local containers. Compose uses fixed container names; keep the same Compose project identity when reusing an existing installation.

### 1. Configure Kong and the server

Run from the repository root:

```bash
cp sensitive-transport-crypto/.env.example sensitive-transport-crypto/.env
cp server/.env.example server/.env
openssl rand -hex 32
```

Use the generated random value for both `ENCRYPTPII_GATEWAY_TOKEN` in the plugin `.env` and `KONG_CRYPTO_GATEWAY_TOKEN` in `server/.env`. Replace all template placeholders, especially the Vault token, secret path, and key alias. Do not commit actual `.env` files.

The plugin scripts resolve `sensitive-transport-crypto/.env` relative to their own location, not the shell's working directory. Exported environment variables take precedence. The scripts accept literal assignments and quoted values but do not execute commands or expand variables inside the file.

The server imports `optional:file:./server/.env[.properties]` through Spring configuration. Start it with the repository root as the working directory, including in an IDE. With a different working directory, override `SPRING_CONFIG_IMPORT` with the appropriate `.env[.properties]` path. Use unquoted `KEY=value` entries in the Spring `.env`, and restart Spring after editing it.

Spring resolves `KONG_CRYPTO_GATEWAY_TOKEN` first, falling back to `ENCRYPTPII_GATEWAY_TOKEN` if available in its configuration environment. Merely creating a `.env` file does not export its values to other processes.

### 2. Prepare Vault key material

The configured secret must contain these fields:

```json
{
  "publicKey": "<Base64 X.509 SubjectPublicKeyInfo DER>",
  "privateKey": "<Base64 PKCS#8 private-key DER>"
}
```

Both fields must belong to the same RSA key pair. The rotation script generates RSA-2048 keys in this format. It requires an existing readable secret and does not bootstrap a missing path; provision the initial key pair in Vault before using it.

An example configuration is:

| Plugin variable | Example / purpose |
| --- | --- |
| `KONG_ADMIN_URL` | `http://localhost:8001` |
| `KONG_ADMIN_GUI_URL` | `http://localhost:8002` |
| `KONG_ADMIN_GUI_API_URL` | `http://localhost:8001` |
| `ENCRYPTPII_UPSTREAM_URL` | `http://host.docker.internal:9090` |
| `ENCRYPTPII_VAULT_ADDR` | `http://host.docker.internal:8200` |
| `ENCRYPTPII_VAULT_SECRET_PATH` | `secret/data/sensitive-transport-crypto/rsa-ciam` |
| `ENCRYPTPII_KEY_ALIAS` | `rsa-ciam`; used in `keyId`, not derived from the path |
| `ENCRYPTPII_VAULT_TOKEN` | Token with read access to the data and metadata paths |
| `ENCRYPTPII_GATEWAY_TOKEN` | Random secret shared with the Spring server |
| `ENCRYPTPII_KEY_VALIDITY_MILLIS` | `3600000` (one hour) |
| `ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS` | `600000` (ten minutes) |
| `ENCRYPTPII_MAX_BODY_BYTES` | `1048576` (one MiB) |

`host.docker.internal` lets the Kong container reach services on the host in the local Docker Desktop setup. Adjust addresses for other deployments.

### 3. Install the plugin and routes

```bash
./sensitive-transport-crypto/scripts/install-to-kong.sh
```

The installer builds the custom Kong image, starts the Compose services, waits for the Admin API, and idempotently creates or updates the service, routes, and plugin instances.

| Address | Purpose |
| --- | --- |
| `http://localhost:8000` | Kong proxy used by the Java client |
| `http://localhost:8001` | Kong Admin API |
| `http://localhost:8002` | Kong Manager |
| `http://localhost:9090` | Plaintext Spring upstream |
| `http://localhost:8080` | Java demo client |

The browser origin must match `KONG_ADMIN_GUI_URL`; mixing `localhost` and `127.0.0.1` can cause CORS failures in Manager.

### 4. Start the applications

Run these commands from the repository root in separate terminals:

```bash
./gradlew :server:bootRun
```

```bash
./gradlew :client:bootRun
```

The client configuration points to Kong at `http://localhost:8000`, not directly to the Spring server.

### 5. Call the demo client

```bash
curl --fail-with-body http://localhost:8000/crypto/server/public-key

curl --fail-with-body -X POST http://localhost:8080/crypto/client/bidirectional \
  -H 'Content-Type: application/json' \
  --data '{"name":"demo","phone":"1234567890","email":"demo@example.com","address":"demo address"}'
```

The client also exposes `POST /crypto/client/request-only` with the same request shape and `POST /crypto/client/response-only` with an optional body such as `{"data":"demo"}`. Demo responses include plaintext, ciphertext, and timing information; do not expose these diagnostic APIs in production.

## Kong plugin behavior

The Lua plugin type is `sensitive-transport-crypto`. Route configuration creates four instances of that same plugin type:

| Public route | Method | Upstream path | Plugin behavior |
| --- | --- | --- | --- |
| `/crypto/server/public-key` | GET | None | Read Vault and respond directly |
| `/crypto/server/bidirectional` | POST | `/crypto/kong/bidirectional` | Decrypt request; encrypt response |
| `/crypto/server/request-only` | POST | `/crypto/kong/request-only` | Decrypt request; leave response plaintext |
| `/crypto/server/response-only` | POST | `/crypto/kong/response-only` | Decrypt session-key headers; encrypt response |

Repeated plugin names in Manager are expected: distinguish instances by their associated route.

The public-key endpoint returns `publicKeyBase64`, `keyId`, and `expiresAtEpochMillis` with `Cache-Control: no-store`. It reads the current Vault version on each request and never returns private-key material.

For request-body encryption, the wire format is:

```json
{
  "keyId": "rsa-ciam:1",
  "encryptedSessionKeyBase64": "<RSA-OAEP ciphertext>",
  "ivBase64": "<12-byte IV>",
  "encryptedDataBase64": "<AES-GCM ciphertext followed by the 16-byte authentication tag>"
}
```

Response-only mode transports the RSA-encrypted AES key in `X-STC-SESSION-KEY` and the version identifier in `X-STC-KEY-ID`. Kong removes these headers before forwarding. Encrypted responses contain `ivBase64` and `encryptedDataBase64`.

RSA uses OAEP SHA-256 with MGF1-SHA-1, matching the Java implementation. AES uses 256-bit GCM, a 12-byte IV, and a 16-byte tag.

Kong authenticates to the upstream using `X-Crypto-Gateway-Token`. The server returns 503 if its configured token is empty and 403 if the supplied token is missing or incorrect. This token is independent of the RSA key pair and does not change during Vault key rotation.

## Key management

### Ownership and permissions

Vault KV v2 stores versioned key material; it does not automatically generate or rotate these RSA keys. The Spring business server has no Vault dependency. Kong reads keys, while the manual rotation script writes new versions.

Use separate tokens in production:

| Identity | Required Vault capabilities |
| --- | --- |
| Kong | `read` on the configured KV v2 data and metadata paths |
| Rotation script | `read` and `update` on the existing KV v2 data path |

For `secret/data/sensitive-transport-crypto/rsa-ciam`, the metadata path is `secret/metadata/sensitive-transport-crypto/rsa-ciam`. Isolate paths and aliases per application or security boundary.

### Rotate an existing key

From the repository root:

```bash
# Read the configured secret and prepare keys without writing.
./sensitive-transport-crypto/scripts/rotate-vault-key.sh --dry-run

# Generate a new key pair and persist a new Vault version.
./sensitive-transport-crypto/scripts/rotate-vault-key.sh

# Override the target path and use a dedicated rotation token.
VAULT_ADDR=http://localhost:8200 VAULT_TOKEN='<rotation-token>' \
  ./sensitive-transport-crypto/scripts/rotate-vault-key.sh \
  secret/data/sensitive-transport-crypto/rsa-ciam
```

The script reads the plugin `.env`, preserves unrelated fields, and uses the version it read as a KV v2 CAS condition. A competing update causes failure instead of overwriting newer data. Inspect the latest version before retrying. Old versions are not deleted.

For host execution, the script converts `host.docker.internal` from the plugin configuration to `localhost`, preserving the port and path. An explicit `VAULT_ADDR` is used unchanged. Temporary key files have restrictive permissions and are removed on exit; tokens and key material are not printed.

After a successful write, the next public-key request reads the new version without a Kong restart. Business requests select private keys by their `keyId`. Parsed private keys are cached per worker for up to 60 seconds, so not every business request re-reads Vault.

### Expiration and grace period

The plugin computes public-key expiration as:

```text
expiresAtEpochMillis = Vault version created_time + key_validity_millis
```

Expired current public keys are not issued to clients: the public-key route returns 503. Reinstalling Kong or reapplying routes does not reset the Vault creation time.

Historical private-key versions are checked against:

```text
historical deadline = created_time + key_validity_millis + key_grace_period_millis
```

The grace period applies to historical-key decryption, not to serving an expired public key. Retain old Vault versions through this window. Worker caches can delay observing version changes; the cache is not an immediate key-revocation mechanism.

There is currently no automatic rotation scheduler in Kong or Spring. Arrange an external job to run the rotation script before expiry, with failure monitoring and overlap prevention. Otherwise manual rotation is required whenever the active key expires. Coordinate validity, client key refresh, and Vault version retention rather than repeatedly extending validity to avoid rotation.

## Operational scripts

All commands below can be run from the repository root:

```bash
./sensitive-transport-crypto/scripts/build-plugin.sh
./sensitive-transport-crypto/scripts/configure-routes.sh
./sensitive-transport-crypto/scripts/install-to-kong.sh
```

`build-plugin.sh` builds the image and checks Lua compilation. `configure-routes.sh` changes persisted routing and plugin settings without restarting Kong. `install-to-kong.sh` also updates the container environment; use it after changing the Vault or gateway token. Build alone does not deploy a new image to the running container.

For manual Compose operations, explicitly select the plugin configuration file:

```bash
docker compose --env-file sensitive-transport-crypto/.env \
  -f sensitive-transport-crypto/docker-compose.yml ps
```

## Troubleshooting

| Symptom | Likely cause / action |
| --- | --- |
| Public-key route returns 503 | Check `docker logs kong`: expired key, unreadable Vault secret/metadata, invalid key fields, or token/connectivity failure |
| Business route returns 503 with an encrypted body | Upstream errors can be encrypted; check the Spring gateway token and Kong logs |
| Business route returns 403 | Spring and Kong shared tokens differ, or the internal endpoint was called directly |
| Container name conflict | Existing containers belong to a different Compose project; preserve its project identity and database volume rather than deleting data |
| Manager shows no resources | Check Admin API availability and the configured Manager origin/API URL |
| Host cannot resolve `host.docker.internal` | Use `localhost` for host-side operations; the rotation script handles the plugin address automatically |
| Spring cannot load `server/.env` | Check the process working directory, import path, and restart the application |

## Production boundaries

The Compose configuration is a local demo, not a hardened deployment. Replace demonstration database/UI credentials, restrict Admin API and Manager access, and protect the internal Spring routes with network controls as well as the shared token.

Use HTTPS for client-to-Kong, Kong-to-server, and Vault connections. Do not log decrypted payloads, key material, or authentication tokens. Kong buffers bodies; the plugin supports a maximum configured size of 16 MiB, with a typical setting of 1 MiB. This implementation is not a streaming encryption solution.

For detailed plugin configuration, see [sensitive-transport-crypto/README.md](sensitive-transport-crypto/README.md).
