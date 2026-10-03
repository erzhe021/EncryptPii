# EncryptPii

EncryptPii demonstrates application-level encryption of sensitive data using a Java client, a Lua Kong plugin, and HashiCorp Vault KV v2.
Kong handles public-key delivery, request decryption, and response encryption;
The Spring Boot business server handles plaintext and does not connect to Vault.

从全新本地 Kubernetes 集群开始的中文部署步骤见[本地 Kubernetes 从零部署指南](docs/k8s-quickstart.zh-CN.md)。
清理并彻底重建本地 Kubernetes 部署可使用 `scripts/cleanup-local-k8s.sh` 和 `scripts/rebuild-local-k8s.sh`；脚本会删除 Vault PVC 数据，详情见指南。

独立部署入口：`vault/scripts/deploy-to-k8s.sh`、`server/scripts/deploy-to-k8s.sh`、`sensitive-transport-crypto/scripts/deploy-to-k8s.sh`、`client/scripts/deploy-to-k8s.sh`，按此顺序部署即可；所有组件默认使用 K8s 集群内通信，独立脚本不会删除已有 Vault 数据。Kong 使用已有的 Kubernetes Vault Secret，不会从 `.env` 覆盖令牌。

各组件的 `scripts/delete-from-k8s.sh` 提供独立删除入口，保留共享命名空间；Vault 默认保留 PVC，只有加 `--purge-data` 才删除持久数据。删除操作需输入 `DELETE` 确认，也可用 `--yes` 跳过，具体范围见中文指南。

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
.env.example                    Shared Kong, Vault, and Spring server configuration template
.env                             Local credentials and application settings (Git-ignored)
sensitive-transport-crypto/
  Dockerfile                    Kong 3.7 image containing the Lua plugin
  docker-compose.yml            Kong, PostgreSQL, and migration containers
  kong/plugins/
    sensitive-transport-crypto/  Plugin handler and schema
  scripts/                      Build, installation, and route configuration
  README.md                     Detailed plugin reference
vault/scripts/                  Vault initialization, migration, unseal, and key rotation
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
cp .env.example .env
openssl rand -hex 32
```

Use the generated random value for both `ENCRYPTPII_GATEWAY_TOKEN` and `KONG_CRYPTO_GATEWAY_TOKEN` in the root `.env`. Replace all template placeholders, especially the Vault token, secret path, and key alias. Do not commit `.env`.

The Kong, Vault, and rebuild scripts locate the root `.env` relative to their own paths, not the shell's working directory. Exported environment variables take precedence. The scripts accept literal assignments and quoted values but do not execute commands or expand variables inside the file.

The server imports `optional:file:./.env[.properties]` through Spring configuration. Start it with the repository root as the working directory, including in an IDE. With a different working directory, override `SPRING_CONFIG_IMPORT` with the appropriate root `.env` path. Use unquoted `KEY=value` entries in `.env`, and restart Spring after editing it.

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
| `ENCRYPTPII_UPSTREAM_URL` | `http://encryptpii-server.encryptpii.svc.cluster.local:9090` |
| `ENCRYPTPII_VAULT_ADDR` | `http://vault.vault.svc.cluster.local:8200` |
| `ENCRYPTPII_VAULT_SECRET_PATH` | `secret/data/sensitive-transport-crypto/rsa-ciam` |
| `ENCRYPTPII_KEY_ALIAS` | `rsa-ciam`; used in `keyId`, not derived from the path |
| `ENCRYPTPII_VAULT_TOKEN` | Token with read access to the data and metadata paths |
| `ENCRYPTPII_GATEWAY_TOKEN` | Random secret shared with the Spring server |
| `ENCRYPTPII_KEY_VALIDITY_MILLIS` | `3600000` (one hour) |
| `ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS` | `600000` (ten minutes) |
| `ENCRYPTPII_MAX_BODY_BYTES` | `1048576` (one MiB) |

默认地址用于 K8s 集群内部通信，本机不能直接解析这些 Service 域名。旧 Docker Compose 安装流程需要显式覆盖地址和令牌；推荐使用上面的组件 K8s 部署入口。

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
CRYPTO_SERVER_BASE_URL=http://localhost:8000 ./gradlew :client:bootRun
```

The client's default Kong address is `http://encryptpii-kong.kong.svc.cluster.local:8000` for Kubernetes. The command above overrides it to `http://localhost:8000` for the local Compose setup, not directly to the Spring server.

### 5. Call the demo client

```bash
curl --fail-with-body http://localhost:8000/crypto/server/public-key

curl --fail-with-body -X POST http://localhost:8080/crypto/client/bidirectional \
  -H 'Content-Type: application/json' \
  --data '{"name":"demo","phone":"1234567890","email":"demo@example.com","address":"demo address"}'
```

The client also exposes `POST /crypto/client/request-only` with the same request shape and `POST /crypto/client/response-only` with an optional body such as `{"data":"demo"}`. Demo responses include plaintext, ciphertext, and timing information; do not expose these diagnostic APIs in production.

## Run the server in local Kubernetes

The repository includes `server/Dockerfile` and `server/k8s/server.yaml` for a local Kubernetes deployment. The manifest creates the `encryptpii` namespace, one server replica, health probes, resource limits, and a ClusterIP service. It expects the local image `encryptpii-server:local` and the Secret `encryptpii-gateway` with a `token` key matching Kong's gateway token.

```bash
./gradlew :server:bootJar
docker build -t encryptpii-server:local server
kubectl apply -f server/k8s/server.yaml
kubectl -n encryptpii rollout status deployment/encryptpii-server
kubectl -n encryptpii port-forward service/encryptpii-server 19090:9090
```

Create the Secret before the server starts, using your secret-management tooling; do not put the token in the manifest. The deployment injects it as `KONG_CRYPTO_GATEWAY_TOKEN`, so the Pod does not need a `.env` file or Vault access.

The image must be loaded into the Kubernetes node runtime before deployment. Docker Desktop clusters using a separate containerd store may not see images built by Docker; import the image into the node's `k8s.io` containerd namespace, or use a registry and adjust the image and pull policy. The checked-in `Never` pull policy is intended only for locally loaded images. After rebuilding the same image tag, import it again and restart the deployment.

The service is available inside the cluster as `encryptpii-server.encryptpii.svc.cluster.local:9090`. Port forwarding exposes it on host `localhost:19090` only while that command runs; it does not automatically redirect the existing Docker Kong upstream. Connecting Docker Kong requires a reachable upstream address and explicit route reconfiguration.

## Run Kong in local Kubernetes

With the Kubernetes server and its `encryptpii-gateway` Secret already deployed, run:

```bash
./sensitive-transport-crypto/scripts/deploy-to-k8s.sh
kubectl -n kong port-forward service/encryptpii-kong \
  18000:8000 18001:8001 18002:8002
```

This Docker Desktop-specific script builds the plugin image, imports it into the local node's containerd runtime using a temporary privileged helper, and removes the helper afterward. It reads the repository-root `.env`, creates the Vault Token Secret and a declarative ConfigMap, and deploys the Gateway manifest at `sensitive-transport-crypto/k8s/kong.yaml`. The existing server gateway Secret is reused; the script does not change the server token.

Kong runs in the separate `kong` namespace, with its ConfigMap and Secrets, while the server remains in `encryptpii`. The deployment script copies the server gateway Secret into `kong` because Secret references cannot cross namespaces. Kong runs DB-less with four route-scoped plugin instances and uses `encryptpii-server.encryptpii.svc.cluster.local:9090` as the upstream. PostgreSQL and Kong Ingress Controller are not deployed. The Vault address comes from the root `.env`; Vault remains external to Kubernetes. Token authentication and manual rotation are unchanged.

While port forwarding is running, use proxy `http://localhost:18000`, Admin API `http://localhost:18001`, and Manager `http://localhost:18002`. The Docker Kong installation is left intact. To direct the Java client to Kubernetes Kong, set `CRYPTO_SERVER_BASE_URL=http://localhost:18000` when starting the client.

Do not use `configure-routes.sh` against this DB-less Gateway: CRUD configuration through the Admin API is not supported in this mode. Rerun `deploy-to-k8s.sh` to regenerate configuration and restart Kong after settings or secrets change. If public-key requests return 503 because the existing Vault key has expired, rotate it with `./vault/scripts/rotate-vault-key.sh`; deploying Kong does not renew keys.

## Run the client in local Kubernetes

`client/Dockerfile` and `client/k8s/client.yaml` deploy the client in the `encryptpii` namespace. Its `CRYPTO_SERVER_BASE_URL` is set to `http://encryptpii-kong.kong.svc.cluster.local:8000`, matching the application default, so client-to-Kong traffic uses cluster networking without host port forwarding.

```bash
./gradlew :client:bootJar
docker build -t encryptpii-client:local client
# Import the image into the local Kubernetes node runtime, as for the server.
kubectl apply -f client/k8s/client.yaml
kubectl -n encryptpii rollout status deployment/encryptpii-client
kubectl -n encryptpii get service encryptpii-client
```

The manifest uses a locally loaded image with `imagePullPolicy: Never`, a LoadBalancer Service on port 18080 targeting container port 8080, health probes, and a non-root container. Once the Docker Desktop load balancer is ready, host access to demo APIs is directly through `http://localhost:18080/crypto/client/*`, without port forwarding. Kong and server do not require separate port forwards for those calls. If the cluster does not provide a load balancer, `bash client/scripts/port-forward.sh` remains a debugging fallback. All three components must be healthy and Vault must have an unexpired public key for encrypted business calls to succeed.

## Plaintext demo through Kong

Client exposes a single plaintext POST endpoint `/plain/client/normal`. It does not fetch keys or encrypt/decrypt payloads and returns the upstream response body and status. Its target is configured by `plain.server.endpoints.normal`, currently `/plain/server/normal`.

Kong forwards POST `/plain/server/normal` unchanged to Server `/plain/server/normal` using a separate `encryptpii-server-plain` service with `strip_path: false` and no plugins. The existing encrypted routes remain unchanged. Both the Kubernetes deployment script and the Admin API configuration script install this route. Redeploy Client, Server, and Kong after changing code/configuration. This plaintext path is for local demonstrations, not production exposure of sensitive data.

Client 的目标 URL 统一配置在 `client/src/main/resources/application.yml`：`crypto.server` 配置加密链路（含公钥接口），`plain.server` 配置非加密链路。两组各有 `base-url` 和 `endpoints`；明文默认复用加密链路的 Kong 地址，可通过 `PLAIN_SERVER_BASE_URL` 单独覆盖。原有 `CRYPTO_SERVER_BASE_URL` 仍有效；修改目标路径时需同步 Kong 路由。

```bash
curl --fail-with-body -X POST http://localhost:18080/plain/client/normal \
  -H 'Content-Type: application/json' \
  --data '{"data":"demo"}'
```

## Run persistent Vault in local Kubernetes

`vault/k8s/vault.yaml` deploys a single-node Raft Vault in namespace `vault`, with a 1 GiB PVC, StatefulSet, and ClusterIP Service. The cluster address used by Kong is `http://vault.vault.svc.cluster.local:8200`.

```bash
./vault/scripts/deploy-to-k8s.sh
./sensitive-transport-crypto/scripts/deploy-to-k8s.sh
```

Vault 部署脚本首次运行会初始化、解封、创建密钥和应用令牌；重复运行保留已有数据。无需安装本机 Docker Vault。仅在需要迁移旧数据时使用 `vault/scripts/initialize-and-migrate.sh`，它不是常规部署步骤。

The migration script reads the root `.env` for the source path/token; `SOURCE_VAULT_ADDR` and `SOURCE_VAULT_TOKEN` can override the source. It copies readable retained versions in ascending order into a new `secret/` KV v2 mount. Destination versions and creation times are new, not an exact Vault backup/restore. For the initial migration, source versions 29–38 became destination versions 1–10. Reset client public-key caches after switching Vaults (for the demo, restart the client Deployment). Deleted/destroyed versions cause migration to stop. An existing destination mount also causes a stop to prevent overwriting data; the script is not a general incremental synchronizer.

Initialization credentials and separate Kong/rotation tokens are stored with restrictive permissions in `vault/.local/`, which is Git-ignored. Back up those files securely outside the repository; never commit or share them. Kong receives a read-only Token through its Kubernetes Secret; the rotation token has read/update access to the target data path. Tokens request a 30-day TTL, subject to Vault limits, and are not automatically renewed by the plugin. Monitor their actual expiry, renew or replace them, update Kong's Secret, and restart Kong when its token changes.

Vault uses manual unseal. After a Pod restart:

```bash
./vault/scripts/unseal.sh
```

Do not delete its PVC or local credentials as routine cleanup. PVC persistence does not protect against deleting/resetting the local cluster or storage; arrange backups. This local setup has one node, a single unseal share, and HTTP without TLS; it is not a production HA or auto-unseal configuration.

To access the Kubernetes Vault from the host:

```bash
kubectl -n vault port-forward service/vault 18200:8200
```

Port forwarding is optional for UI or HTTP access. Rotate the Kubernetes key directly without port forwarding:

```bash
./vault/scripts/rotate-vault-key.sh
```

Rotation defaults to `kubectl exec` in the `docker-desktop` context and reads `vault/.local/rotation-token`; `VAULT_TOKEN` can override it. HTTP access to an external Vault requires `--http`. Kong deployment always uses the internal Kubernetes Vault address and its existing Secret; `--vault-in-k8s` is no longer required.

本地环境变量统一配置在仓库根目录 `.env` 中。

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
./vault/scripts/rotate-vault-key.sh --dry-run

# Generate a new key pair and persist a new Vault version.
./vault/scripts/rotate-vault-key.sh

# Access an external Vault over HTTP with a dedicated rotation token.
VAULT_ADDR=http://localhost:8200 VAULT_TOKEN='<rotation-token>' \
  ./vault/scripts/rotate-vault-key.sh --http \
  secret/data/sensitive-transport-crypto/rsa-ciam
```

The script reads the root `.env`, preserves unrelated fields, and uses the version it read as a KV v2 CAS condition. A competing update causes failure instead of overwriting newer data. Inspect the latest version before retrying. Old versions are not deleted.

By default, keys are generated on the host and read/written through the Vault Pod CLI using `kubectl exec`; no port forwarding is needed. The token and write payload are sent through standard input, not command-line arguments. In `--http` mode, the script converts `host.docker.internal` from the root configuration to `localhost`, preserving the port and path. An explicit `VAULT_ADDR` is used unchanged. Temporary key files have restrictive permissions and are removed on exit; tokens and key material are not printed.

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

For manual Compose operations, explicitly select the root configuration file:

```bash
docker compose --env-file .env \
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
| Spring cannot load the root `.env` | Check the process working directory, import path, and restart the application |

## Production boundaries

The Compose configuration is a local demo, not a hardened deployment. Replace demonstration database/UI credentials, restrict Admin API and Manager access, and protect the internal Spring routes with network controls as well as the shared token.

Use HTTPS for client-to-Kong, Kong-to-server, and Vault connections. Do not log decrypted payloads, key material, or authentication tokens. Kong buffers bodies; the plugin supports a maximum configured size of 16 MiB, with a typical setting of 1 MiB. This implementation is not a streaming encryption solution.

For detailed plugin configuration, see [sensitive-transport-crypto/README.md](sensitive-transport-crypto/README.md).
