# EncryptPii

EncryptPii demonstrates application-level encryption using a Java client, a Lua Kong plugin, and HashiCorp Vault KV v2. Kong delivers public keys, decrypts requests, and encrypts responses. The Spring Boot business server processes plaintext and does not connect to Vault.

This README is the consolidated setup and operations guide. The default deployment runs **Client, Kong, Server, and Vault in local Kubernetes**. The scripts target Docker Desktop Kubernetes and require the `docker-desktop` context; they are not portable to other clusters without adapting image loading and deployment assumptions.

## Architecture

```text
Host http://localhost:18080
  |
  v
Client LoadBalancer (18080 -> container 8080), namespace encryptpii
  |
  v
Kong Service (8000), namespace kong ---- read keys ----> Vault (8200), namespace vault
  |
  v
Server Service (9090), namespace encryptpii

Host rotation script ---- kubectl exec / Vault CLI ----> Vault
```

The encrypted flow creates a new AES-256 session key for each business request and transports it with RSA-OAEP. Kong reads the private-key version identified by `keyId`, decrypts the request, and forwards plaintext with `X-Crypto-Gateway-Token`. Response encryption uses the same AES key.

The independent plaintext flow is:

```text
Client POST /plain/client/normal
  -> Kong POST /plain/server/normal (no plugin, strip_path: false)
  -> Server POST /plain/server/normal
```

Encryption is not a substitute for TLS. Client inbound APIs and Kong-to-Server payloads are plaintext. Both plaintext and encrypted demo APIs expose diagnostic or sensitive data and must not be published as production APIs.

## Project layout

```text
.env.example                          Root configuration template
.env                                  Local settings and credentials (Git-ignored)
client/
  src/                                Java client and encryption helpers
  k8s/client.yaml                     Client Deployment and LoadBalancer Service
  scripts/                            Build, deploy, delete, optional port forwarding
server/
  src/                                Plaintext business handlers
  k8s/server.yaml                     Server Deployment and ClusterIP Service
  scripts/                            Build, deploy, delete
kong/
  Dockerfile                          Kong 3.7 image with the Lua plugin
  docker-compose.yml                  Legacy Docker Compose deployment
  k8s/kong.yaml                       DB-less Kong Deployment and Services
  plugins/sensitive-transport-crypto/  Lua handler and schema
  scripts/                            Build, deploy, delete, configuration helpers
  README.md                           Detailed plugin reference
vault/
  k8s/vault.yaml                      Single-node persistent Raft Vault
  scripts/                            Deploy, unseal, rotate, migrate, delete
  .local/                             Private initialization credentials and tokens
scripts/                              Shared tools and cleanup/rebuild orchestration
```

## Kubernetes quick start from scratch

Assume the repository is checked out and a local Kubernetes cluster is ready. No pre-existing Vault, Kong, database, or Java service is required.

### 1. Install tools and check the cluster

Required tools are JDK 17, Docker with Compose, `kubectl`, Bash, `jq`, `curl`, and OpenSSL, plus standard Unix utilities. The included Gradle wrapper downloads Gradle as needed. On macOS with Homebrew:

```bash
brew install kubectl jq
brew install --cask docker temurin@17
```

Start Docker Desktop and enable Kubernetes. From the repository root:

```bash
docker version
docker compose version
kubectl config current-context
kubectl get nodes
java -version
openssl version
```

The context must be `docker-desktop` and the node must be Ready. Image import uses node `desktop-control-plane`. Docker Desktop clusters with a different node layout, kind, minikube, and remote clusters need an adapted image import strategy.

### 2. Configure the root environment file

For a new checkout only:

```bash
cp .env.example .env
chmod 600 .env
openssl rand -hex 32
```

Do not overwrite an existing `.env`. Edit the file and use the generated random value for **both** `ENCRYPTPII_GATEWAY_TOKEN` and `KONG_CRYPTO_GATEWAY_TOKEN`. Configure the key path and alias:

```dotenv
ENCRYPTPII_UPSTREAM_URL=http://encryptpii-server.encryptpii.svc.cluster.local:9090
ENCRYPTPII_VAULT_ADDR=http://vault.vault.svc.cluster.local:8200
ENCRYPTPII_VAULT_SECRET_PATH=secret/data/sensitive-transport-crypto/rsa-ciam
ENCRYPTPII_KEY_ALIAS=rsa-ciam
ENCRYPTPII_KEY_VALIDITY_MILLIS=3600000
ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS=600000
ENCRYPTPII_MAX_BODY_BYTES=1048576
ENCRYPTPII_GATEWAY_TOKEN=<the-generated-random-value>
KONG_CRYPTO_GATEWAY_TOKEN=<the-same-generated-random-value>
```

Do not paste the angle-bracket placeholders literally. No pre-existing `ENCRYPTPII_VAULT_TOKEN` is needed for the Kubernetes workflow: Vault deployment creates the application tokens, and Kong obtains its token from a Kubernetes Secret. Kong deployment fixes its upstream and Vault addresses to the cluster Services rather than taking external addresses or tokens from `.env`.

| Setting | Meaning |
| --- | --- |
| `ENCRYPTPII_VAULT_SECRET_PATH` | KV v2 API data path, such as `secret/data/sensitive-transport-crypto/rsa-ciam` |
| `ENCRYPTPII_KEY_ALIAS` | Prefix in `keyId`, such as `rsa-ciam`; independent of the secret path |
| `ENCRYPTPII_KEY_VALIDITY_MILLIS` | Public-key lifetime, 1 through 31536000000 ms |
| `ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS` | Historical-key decryption grace, 0 through 31536000000 ms |
| `ENCRYPTPII_MAX_BODY_BYTES` | Plugin body limit, 1 through 16777216 bytes; default 1048576 |
| Gateway token variables | Matching shared secret, at least 32 characters; used for initial Server Secret creation |

Shell scripts locate the root `.env` using their own paths, so they work from other directories. Exported variables take precedence. The loader accepts literal `KEY=value` assignments and quotes, but does not execute commands or expand variables inside the file. Never commit `.env`.

### 3. Deploy and initialize Vault

```bash
./vault/scripts/deploy-to-k8s.sh
```

The script deploys a single-node Raft Vault with a 1 GiB PVC in namespace `vault`. On first use it initializes Vault, unseals it, enables `secret/` KV v2, generates the RSA key pair, creates restricted application policies/tokens, and publishes `kong/encryptpii-vault`.

An uninitialized or sealed Pod is not Ready; the script waits for the container to run before initializing/unsealing. Repeated deployment preserves the PVC and existing key versions. It validates that the active version is not deleted/destroyed and that its RSA public/private keys match. It does not rotate expired keys automatically.

Initialization credentials and tokens are stored with restrictive permissions in Git-ignored `vault/.local/`:

| File | Purpose |
| --- | --- |
| `init.json` | Root token and single unseal key |
| `kong-token`, `kong-token.json` | Read-only application token and creation response |
| `rotation-token`, `rotation-token.json` | Dedicated key-rotation token and creation response |

Back up these files securely outside the repository. Automatic management of an existing Vault requires the matching `init.json`. Stale credentials and invalid tokens produce errors rather than silent replacement.

### 4. Deploy Server

```bash
./server/scripts/deploy-to-k8s.sh
```

This builds the Java application and image, imports the image into the Kubernetes node, and deploys Server in namespace `encryptpii`. On first deployment it creates `encryptpii-gateway` from the matching gateway token in `.env`; later deployments preserve the Secret.

The Deployment injects the token as `KONG_CRYPTO_GATEWAY_TOKEN`. The Pod does not need `.env` or Vault access. The Service remains ClusterIP at `encryptpii-server.encryptpii.svc.cluster.local:9090`; no LoadBalancer or host forwarding is needed.

Encrypted-flow handlers under `/crypto/server/*` require the gateway token. The separate `/plain/server/normal` demo accepts `DemoPlainRequest` without that token.

### 5. Deploy Kong

```bash
./kong/scripts/deploy-to-k8s.sh
```

This builds the custom Kong image, imports it, generates the declarative ConfigMap, copies the Server gateway Secret into namespace `kong`, and deploys DB-less Kong. It uses `vault.vault.svc.cluster.local:8200` and the existing `kong/encryptpii-vault` Secret. **No `--vault-in-k8s` flag is required**; the old flag remains compatible.

Kong has four route-scoped crypto plugin instances and one separate plaintext route without plugins. Neither PostgreSQL nor Kong Ingress Controller is required. Do not use `configure-routes.sh` against this DB-less deployment: Admin API CRUD is not supported. Rerun the deployment script after route, plugin-setting, image, or Secret changes.

### 6. Deploy Client

```bash
./client/scripts/deploy-to-k8s.sh
kubectl -n encryptpii get service encryptpii-client
```

Client runs in namespace `encryptpii` and connects to Kong through `http://encryptpii-kong.kong.svc.cluster.local:8000`. Its LoadBalancer exposes port **18080**, targeting container port **8080**.

Once the Docker Desktop LoadBalancer is ready, access `http://localhost:18080` directly. No Client, Kong, Server, or Vault port-forward process is required for normal demo calls. If the cluster cannot provide a LoadBalancer, use `bash client/scripts/port-forward.sh` as a temporary fallback after ensuring local port 18080 is free.

### 7. Call the demo APIs

```bash
curl --fail-with-body http://localhost:18080/actuator/health

curl --fail-with-body -X POST http://localhost:18080/crypto/client/bidirectional \
  -H 'Content-Type: application/json' \
  --data '{"name":"demo","phone":"1234567890","email":"demo@example.com","address":"demo address"}'

curl --fail-with-body -X POST http://localhost:18080/plain/client/normal \
  -H 'Content-Type: application/json' \
  --data '{"data":"demo"}'
```

The encrypted Client also exposes `POST /crypto/client/request-only` with the sensitive request above and `POST /crypto/client/response-only` with an optional `{"data":"demo"}` body. Encrypted demo responses include plaintext, ciphertext, and latency information.

The only plaintext Client endpoint is `POST /plain/client/normal`. It accepts `DemoPlainRequest`, performs no key lookup or encryption, and returns the upstream response body and status. Server `/plain/server/normal` returns `DemoPlainResponse`.

## Client configuration and Kong routing

All Client target URLs are configured in `client/src/main/resources/application.yml`:

```yaml
crypto:
  server:
    base-url: http://encryptpii-kong.kong.svc.cluster.local:8000
    endpoints:
      public-key: /crypto/server/public-key
      bidirectional: /crypto/server/bidirectional
      request-only: /crypto/server/request-only
      response-only: /crypto/server/response-only
plain:
  server:
    base-url: ${crypto.server.base-url}
    endpoints:
      normal: /plain/server/normal
```

`crypto.server` configures encrypted calls; `plain.server` configures plaintext calls. The latter defaults to the same Kong address, but `PLAIN_SERVER_BASE_URL` can override it independently. `CRYPTO_SERVER_BASE_URL` overrides the encrypted address and, unless independently overridden, the plaintext address. Controllers do not hardcode their upstream endpoint URLs.

| Kong route | Method | Server destination | Behavior |
| --- | --- | --- | --- |
| `/crypto/server/public-key` | GET | None | Plugin reads Vault and responds directly |
| `/crypto/server/bidirectional` | POST | `/crypto/server/bidirectional` | Decrypt request and encrypt response |
| `/crypto/server/request-only` | POST | `/crypto/server/request-only` | Decrypt request; plaintext response |
| `/crypto/server/response-only` | POST | `/crypto/server/response-only` | Decrypt session-key headers; encrypt response |
| `/plain/server/normal` | POST | `/plain/server/normal` | No plugin; preserve path and plaintext body |

The plaintext route uses a separate `encryptpii-server-plain` Kong Service with `strip_path:false`. Do not attach the crypto plugin globally or to this Service, as that would affect the plaintext flow. Keep Client endpoint configuration and Kong routes synchronized when changing paths.

## Builds, redeployment, and image loading

Client, Server, and Kong deployment scripts build and import local images and restart their Deployments. They accept `--skip-build` only when the corresponding image has already been built. Build-only commands are:

```bash
./server/scripts/build-image.sh
./client/scripts/build-image.sh
./kong/scripts/build-plugin.sh
```

`scripts/import-local-k8s-images.sh` is shared by all three deployments. It uses a temporary privileged node-debug Pod to import Docker images into containerd's `k8s.io` namespace and removes the helper on exit.

The manifests use `imagePullPolicy: Never`. A Docker build alone does not make an image available to a separate Kubernetes containerd store; reimport and redeploy after rebuilding the same tag. Other clusters should use their supported image-loading mechanism or a registry with an appropriate pull policy.

## Cleanup and rebuild

### Delete individual components

```bash
./client/scripts/delete-from-k8s.sh
./kong/scripts/delete-from-k8s.sh
./server/scripts/delete-from-k8s.sh
./vault/scripts/delete-from-k8s.sh
```

All deletion scripts require `docker-desktop`, prompt for `DELETE`, and accept `--yes` to bypass confirmation. They retain namespaces and local files. Component deletion logic is shared in `scripts/lib/`; orchestration calls the component entry points.

| Component | Deleted resources | Retained resources |
| --- | --- | --- |
| Client / Server | Own Deployment and Service | Shared gateway Secret |
| Kong | Deployment, Service, ConfigMap, gateway/Vault Secret copies | Server gateway Secret, Vault data |
| Vault | StatefulSet, Services, ConfigMap | PVC, Kong Vault Secret, local credentials |

Redeploying Vault with its retained PVC and matching local credentials restores it. To destroy its persistent data explicitly:

```bash
./vault/scripts/delete-from-k8s.sh --purge-data
```

This additionally deletes `vault/data-vault-0`, associated PV objects, and `kong/encryptpii-vault`. It does not delete local credentials or change `.env`. Before initializing a fresh Vault, securely archive the old `init.json`, `kong-token*`, and `rotation-token*` files. Deleting a PV object does not securely erase underlying storage, particularly with `Retain`.

### Destroy the complete local deployment

```bash
./scripts/cleanup-local-k8s.sh
# Noninteractive, destructive:
./scripts/cleanup-local-k8s.sh --yes
```

This calls component deletion and then removes the entire `vault`, `kong`, and `encryptpii` namespaces, including remaining resources, and associated Vault PV objects. **Vault keys and initialization state are lost. This cannot be undone.** Do not use these shared namespace names for unrelated workloads.

### Rebuild from scratch

After installing tools and configuring `.env`:

```bash
./scripts/rebuild-local-k8s.sh
```

The script validates configuration and builds Server, Client, and Kong before destructive cleanup, so a build failure does not first remove the existing deployment. Cleanup still requires typing `DELETE`. It then archives old local credentials into `vault/.local/previous-*`, initializes a new Vault and RSA key pair, creates restricted tokens, generates a new gateway token, and deploys all components.

Deployment reuses the prebuilt images with `--skip-build`. New credentials remain in `vault/.local/`. Use `http://localhost:18080` after the Client LoadBalancer is ready. Rebuild changes keys and tokens; old encrypted requests and old application tokens cannot be reused.

## Key management

### Key format and permissions

Vault KV v2 stores the following fields in each RSA key version:

```json
{
  "publicKey": "<Base64 X.509 SubjectPublicKeyInfo DER>",
  "privateKey": "<Base64 PKCS#8 private-key DER>"
}
```

The public and private keys must form the same RSA-2048 pair. KV v2 stores versions but does not automatically generate or rotate keys. Initial generation is performed by Vault deployment; later rotation is explicit.

| Identity | Vault capabilities |
| --- | --- |
| Kong | `read` on the configured data and metadata paths |
| Rotation script | `read` and `update` on the existing data path |

For `secret/data/sensitive-transport-crypto/rsa-ciam`, the metadata path is `secret/metadata/sensitive-transport-crypto/rsa-ciam`. Isolate paths and aliases per application or security boundary.

Tokens request a 720-hour TTL, subject to Vault limits. The plugin does not renew them automatically. Monitor actual expiry, renew or replace tokens, update Kong's Secret, and restart Kong after changing its token. Invalid stored tokens cause deployment to fail rather than silently issue replacements.

### Rotate an existing key

```bash
# Read and prepare keys without writing:
./vault/scripts/rotate-vault-key.sh --dry-run

# Write a new key version:
./vault/scripts/rotate-vault-key.sh
```

The script generates RSA keys locally and accesses `vault/vault-0` through `kubectl exec` and the Pod's Vault CLI. It reads `vault/.local/rotation-token` by default; explicit `VAULT_TOKEN` overrides it. No port forwarding is needed. Tokens and JSON payloads are passed through standard input rather than Pod command-line arguments.

The path defaults to `.env` and can be passed as a positional argument. The target secret must already exist. Rotation preserves unrelated fields and uses the read version as a CAS condition; a competing update fails rather than overwriting newer data. Inspect the latest version before retrying. The script does not explicitly delete historical versions, but Vault retention settings still apply.

Temporary key files have restrictive permissions and are removed on exit; key material and tokens are not printed. For an explicitly external Vault, HTTP mode remains available:

```bash
VAULT_ADDR=http://localhost:8200 VAULT_TOKEN='<rotation-token>' \
  ./vault/scripts/rotate-vault-key.sh --http \
  secret/data/sensitive-transport-crypto/rsa-ciam
```

In HTTP mode only, a configured `host.docker.internal` address is mapped to `localhost`; explicit `VAULT_ADDR` is unchanged. Cluster Service DNS names cannot be resolved directly from the host.

### Expiration, caching, and historical versions

```text
public-key expiration = Vault version created_time + key_validity_millis
historical-key deadline = created_time + key_validity_millis + key_grace_period_millis
```

An expired current public key is not issued: the public-key route returns 503. Deploying Kong or reapplying routes does not reset the Vault creation time. The grace period permits historical-key decryption, not issuing expired public keys. Retain old versions throughout this window.

Kong's public-key endpoint reads the current version for each call and returns `Cache-Control: no-store`; it never returns private-key material. The next public-key request sees a successful rotation without a Kong restart. Client caches its public key until expiry, so it may continue to send an older `keyId`. Parsed private keys are cached per Kong worker for up to 60 seconds; caches are not an immediate key-revocation mechanism.

No automatic rotation scheduler is included. Schedule rotation before expiry with failure monitoring and overlap prevention, coordinating client refresh, grace periods, and Vault version retention.

### Cryptographic wire format

Request-body encryption uses:

```json
{
  "keyId": "rsa-ciam:1",
  "encryptedSessionKeyBase64": "<RSA-OAEP ciphertext>",
  "ivBase64": "<12-byte IV>",
  "encryptedDataBase64": "<AES-GCM ciphertext followed by the 16-byte authentication tag>"
}
```

RSA uses OAEP SHA-256 with MGF1-SHA-1, matching Java. AES uses 256-bit GCM, a 12-byte IV, and a 16-byte tag. Response-only mode sends the RSA-encrypted AES key in `X-STC-SESSION-KEY` and the version in `X-STC-KEY-ID`; Kong removes these headers before forwarding. Encrypted responses contain `ivBase64` and `encryptedDataBase64`.

The gateway token is independent of the RSA pair and does not change during rotation. Encrypted-flow Server handlers return 503 for an empty configured token and 403 for a missing or incorrect supplied token.

## Maintenance and troubleshooting

Check resource status and logs:

```bash
kubectl -n vault get pods,svc,pvc
kubectl -n kong get pods,svc
kubectl -n encryptpii get pods,svc
kubectl -n kong logs deployment/encryptpii-kong
kubectl -n encryptpii logs deployment/encryptpii-server
kubectl -n encryptpii logs deployment/encryptpii-client
```

Vault uses manual unseal. After a Pod restart:

```bash
./vault/scripts/unseal.sh
```

Do not delete its PVC or credentials as routine maintenance. PVC persistence does not protect against local cluster/storage deletion; arrange backups.

For optional Kong proxy/Admin/Manager diagnostics, keep this command running in a separate terminal:

```bash
kubectl -n kong port-forward service/encryptpii-kong \
  18000:8000 18001:8001 18002:8002
```

Then query the public key:

```bash
curl --fail-with-body http://localhost:18000/crypto/server/public-key
```

Use `http://localhost:18001` for Admin API reads and `http://localhost:18002` for Manager. The browser origin must match the Manager configuration; mixing `localhost` and `127.0.0.1` can cause CORS errors. Vault UI/API access is also optional:

```bash
kubectl -n vault port-forward service/vault 18200:8200
```

| Symptom | Action |
| --- | --- |
| Public-key endpoint returns 503 | Check Vault unseal state, token expiry/permissions, data and metadata paths, RSA fields, and key expiration; inspect Kong logs |
| Business call returns 403 | Check the Server/Kong gateway Secrets and whether a protected Server endpoint was called directly |
| Business error response is encrypted | Inspect the decrypted response and Server logs; upstream errors can be encrypted |
| Client uses an older `keyId` after rotation | Client may still cache its unexpired public key; restart Client if immediate refresh is required |
| Client port 18080 is unavailable | Check LoadBalancer readiness and local port conflicts; stop old port-forward processes |
| Local image is not found | Import the image into the node runtime; a Docker build alone may not suffice |
| Host cannot resolve cluster Service DNS | Use Client's LoadBalancer or an explicit diagnostic port forward |
| DB-less Admin API rejects configuration writes | Rerun `kong/scripts/deploy-to-k8s.sh`, not `configure-routes.sh` |
| Vault deployment rejects credentials | Restore credentials matching this PVC; do not overwrite initialization files or discard data |

## Optional legacy workflows

These workflows are not required for the default all-Kubernetes deployment.

### Migrate an existing external Vault

`vault/scripts/initialize-and-migrate.sh` migrates readable retained versions into a fresh Kubernetes Vault. It reads `.env` for the key path and source token; use explicit `SOURCE_VAULT_ADDR` and `SOURCE_VAULT_TOKEN` for the source.

It sets sufficient destination version retention before writing and verifies the migrated versions. Destination version numbers and creation times are new; this is not an exact Vault backup/restore. Deleted/destroyed source versions and an existing destination mount cause a stop. It is not an incremental synchronization tool. Reset Client caches after switching Vaults.

### Docker Compose and host-run applications

The legacy Compose deployment is documented in [kong/README.md](kong/README.md). It requires a separately running Vault and Spring Server, explicit host-reachable address/token overrides, and available ports 5432, 8000, 8001, 8002, 8443, and 8444. Root `.env` now defaults to Kubernetes addresses, so running the legacy installer without overrides is not the recommended setup.

`kong/scripts/build-plugin.sh` builds the image and checks Lua compilation. `configure-routes.sh` manages routes in database-backed Kong; `install-to-kong.sh` starts Compose and applies that configuration. Preserve the Compose project identity and database volume when reusing an installation.

```bash
docker compose --env-file .env -f kong/docker-compose.yml ps
```

For a host-run Client connected to Kubernetes Kong, first start the Kong diagnostic port forward, then:

```bash
CRYPTO_SERVER_BASE_URL=http://localhost:18000 ./gradlew :client:bootRun
```

A host-run Server imports `optional:file:./.env[.properties]`. Start from the repository root, or override `SPRING_CONFIG_IMPORT` with the correct file path. Use unquoted assignments for Spring imports and restart after editing. `KONG_CRYPTO_GATEWAY_TOKEN` takes precedence over `ENCRYPTPII_GATEWAY_TOKEN`.

## Production boundaries

This is a local demo: Vault uses one Raft node, one unseal share, and HTTP without TLS. Use production-grade TLS, HA/auto-unseal, backups, token renewal, and access controls before deploying elsewhere. Protect Admin API/Manager and internal Server endpoints with network controls as well as tokens. The plaintext demo endpoint has no gateway-token authentication.

Do not log decrypted payloads, key material, or credentials. Replace legacy Compose database/UI demonstration credentials. Kong buffers bodies; the plugin supports up to 16 MiB, typically configured to 1 MiB, and is not a streaming encryption solution.

For detailed plugin configuration, see [kong/README.md](kong/README.md).
