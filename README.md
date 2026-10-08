# EncryptPii

EncryptPii 演示如何使用 Java 客户端、Kong Lua 插件和 HashiCorp Vault KV v2 实现应用层加密。Kong 从 Vault 获取 RSA 密钥，在网关解密请求、加密响应；Spring Server 只处理明文业务数据，不直接访问 Vault。

默认部署方式是在 Docker Desktop Kubernetes 中运行 Client、Kong、Server 和 Vault。部署脚本要求当前 Kubernetes context 为 `docker-desktop`，并依赖 Docker Desktop 的本地镜像导入方式；迁移到其他集群前，需要调整镜像分发、存储和部署配置。

> 本项目用于本地演示，不是开箱即用的生产方案。应用层加密不能替代 TLS。客户端到网关、网关到上游之间可能存在明文，演示 API 也会返回诊断或敏感数据，不应直接暴露到公网。

## 架构与数据流

```text
浏览器 / 调用方
    |
    v
Client LoadBalancer :18080                    namespace: encryptpii
    |
    v
Kong Service :8000 / :8443 ------------------> Server Service :9090
    |                                             namespace: encryptpii
    +---- 读取密钥 ----> Vault Service :8200
                         namespace: vault

主机轮换脚本 ---- kubectl exec / Vault CLI ----> Vault
```

加密业务请求由 Client 为每次请求生成 AES-256 会话密钥，并使用 RSA-OAEP 加密会话密钥。Kong 根据 `keyId` 从 Vault 读取对应私钥，解密请求体后将明文转发到 Server，并注入 `X-Crypto-Gateway-Token`。需要加密响应时，Kong 使用同一会话密钥加密响应。

明文演示链路与加密链路分开，不获取公钥、不加解密，也不挂载 Kong 加密插件：

```text
Client POST /plain/client/normal
  -> Kong POST /plain/server/normal
  -> Server POST /plain/server/normal
```

## 项目结构

```text
.env.example                         根目录配置模板
.env                                 本地配置与凭据，不提交 Git
client/                              Java 加密客户端、API 与 Kubernetes 清单
server/                              Spring Boot 明文业务服务与 Kubernetes 清单
kong/                                Kong 插件、镜像、部署脚本和说明
vault/                               Vault 部署、初始化、轮换、迁移脚本和说明
scripts/                             本地 Kubernetes 镜像、清理和重建工具
```

组件细节见 [`kong/README.md`](kong/README.md) 和 [`vault/README.md`](vault/README.md)。

## 从零部署到本地 Kubernetes

### 1. 安装工具并检查集群

需要 JDK 17、Docker Desktop（含 Docker Compose）、`kubectl`、Bash、`jq`、`curl`、OpenSSL 和常用 Unix 工具。项目包含 Gradle Wrapper，会按需下载 Gradle。macOS 可使用：

```bash
brew install kubectl jq
brew install --cask docker temurin@17
```

启动 Docker Desktop 并启用 Kubernetes，然后在仓库根目录检查环境：

```bash
docker version
docker compose version
kubectl config current-context
kubectl get nodes
java -version
openssl version
```

当前 context 必须为 `docker-desktop`，且节点状态为 `Ready`。本地镜像导入脚本默认使用节点 `desktop-control-plane`；kind、minikube、远程集群或不同节点布局需要使用相应的镜像分发方式。

### 2. 配置根目录 `.env`

新检出项目时创建 `.env` 并限制文件权限：

```bash
cp .env.example .env
chmod 600 .env
openssl rand -hex 32
```

将生成的随机值填入 `KONG_TO_ENCRYPTPII_AUTH_TOKEN`，不要把尖括号占位符原样写入配置。密钥别名和 Vault 路径需在 Client、Kong、Server 的部署配置中保持一致。

```dotenv
ENCRYPTPII_UPSTREAM_URL=http://encryptpii-server.encryptpii.svc.cluster.local:9090
ENCRYPTPII_VAULT_ADDR=http://vault.vault.svc.cluster.local:8200
ENCRYPTPII_VAULT_SECRET_PATH=secret/data/sensitive-transport-crypto/rsa-ciam
ENCRYPTPII_KEY_ALIAS=rsa-ciam
ENCRYPTPII_KEY_VALIDITY_MILLIS=3600000
ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS=600000
ENCRYPTPII_MAX_BODY_BYTES=1048576
KONG_TO_ENCRYPTPII_AUTH_TOKEN=填入生成的随机值
```

| 配置项 | 说明 |
| --- | --- |
| `ENCRYPTPII_VAULT_SECRET_PATH` | KV v2 data 路径，例如 `secret/data/sensitive-transport-crypto/rsa-ciam` |
| `ENCRYPTPII_KEY_ALIAS` | `keyId` 中的别名部分，例如 `rsa-ciam`，与 Vault 路径相互独立 |
| `ENCRYPTPII_KEY_VALIDITY_MILLIS` | 当前公钥有效期，范围 1–31536000000 毫秒 |
| `ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS` | 旧版本解密宽限期，范围 0–31536000000 毫秒 |
| `ENCRYPTPII_MAX_BODY_BYTES` | 插件请求/响应缓冲上限，范围 1–16777216 字节，默认 1048576 |
| `KONG_TO_ENCRYPTPII_AUTH_TOKEN` | Kong 到 Server 的共享认证密钥，至少 32 个字符，Server 与 Kong 必须一致 |
| `KONG_TLS_CERT_FILE`、`KONG_TLS_KEY_FILE` | Kong HTTPS 的 PEM 证书和私钥路径，相对仓库根目录或绝对路径；证书 SAN 必须匹配访问域名 |

脚本从自身路径定位仓库根目录，因此可从其他工作目录运行。已导出的环境变量优先于 `.env`。配置文件只读取字面量 `KEY=value` 及引号，不执行 shell 命令，也不展开变量。不要提交 `.env`。

Kong 使用 Kubernetes ServiceAccount 访问 Vault，不在 Kong 插件配置中设置静态 Vault token。外部 Vault 迁移需要显式提供 `SOURCE_VAULT_TOKEN`；密钥轮换使用单独的 rotation token。

### 3. 部署并初始化 Vault

```bash
./vault/scripts/deploy-to-k8s.sh
```

脚本部署单节点 Raft Vault 和 1 GiB PVC 到 `vault` namespace。首次运行会初始化并解封 Vault、启用 `secret/` KV v2 和 Kubernetes auth、创建 Kong 只读 ServiceAccount role 与专用轮换 policy/token，并在配置的路径生成初始 RSA 密钥。

初始化凭据及轮换 token 存放于 Git 忽略的 `vault/.local/`：

| 文件 | 用途 |
| --- | --- |
| `init.json` | Vault root token 与解封密钥 |
| `rotation-token`、`rotation-token.json` | 专用轮换 token 及创建响应 |

安全备份这些文件，不要提交或公开。已有 Vault 必须配套使用与其数据匹配的 `init.json`。重复部署保留 PVC 和现有密钥版本，不会自动轮换。旧部署中的 `kong-token*` 文件已不用于当前 Kubernetes Kong。

### 4. 部署 Server

```bash
./server/scripts/deploy-to-k8s.sh
```

脚本构建并导入 Server 镜像，部署至 `encryptpii` namespace；每次部署会根据 `.env` 同步共享的 `encryptpii-gateway` Secret。Server 只需要该 token，不需要 `.env` 或 Vault 访问权限。

Server 集群内地址为 `http://encryptpii-server.encryptpii.svc.cluster.local:9090`。`/crypto/server/*` 受网关 token 保护；`/plain/server/normal` 是独立的演示明文接口。

### 5. 部署 Kong

```bash
./kong/scripts/deploy-to-k8s.sh
```

脚本构建并导入自定义 Kong 镜像、生成 DB-less 声明式配置、将 Server 的 gateway Secret 复制到 `kong` namespace 并部署。Kong 通过 `kong/encryptpii-kong` ServiceAccount 使用 Vault 的 `encryptpii-kong` Kubernetes auth role 获取短期 token；Vault 地址为集群内的 `vault.vault.svc.cluster.local:8200`。

部署前需在 `.env` 配置 TLS 证书/私钥路径并准备好 PEM 文件；脚本会创建 TLS Secret 并启用 Kong 的 `8443` HTTPS 代理端口。证书生成和本机 HTTPS 测试示例见 [`kong/README.md`](kong/README.md)。Kong 配置了四条加密路由和一条不挂插件的明文路由。不需要 PostgreSQL 或 Kong Ingress Controller。DB-less 模式不支持通过 Admin API 写入配置，因此不要对该部署运行 `configure-routes.sh`；修改路由、插件配置、镜像或 Secret 后重新运行部署脚本。

### 6. 部署 Client

```bash
./client/scripts/deploy-to-k8s.sh
kubectl -n encryptpii get service encryptpii-client
```

Client 在 `encryptpii` namespace 中运行，通过 `http://encryptpii-kong.kong.svc.cluster.local:8000` 访问 Kong。Docker Desktop 的 LoadBalancer 将主机端口 `18080` 转发到 Client 容器端口 `8080`。LoadBalancer 就绪后可直接访问，无需启动其他组件的端口转发：

```text
http://localhost:18080
```

如果集群不能提供 LoadBalancer，可在确认本机端口 `18080` 空闲后通过 Kubernetes 临时转发：

```bash
kubectl -n encryptpii port-forward service/encryptpii-client 18080:18080
```

### 7. 调用演示 API

```bash
curl --fail-with-body http://localhost:18080/actuator/health

curl --fail-with-body -X POST \
  http://localhost:18080/crypto/client/bidirectional \
  -H 'Content-Type: application/json' \
  --data '{"name":"demo","phone":"1234567890","email":"demo@example.com","address":"demo address"}'

curl --fail-with-body -X POST \
  http://localhost:18080/plain/client/normal \
  -H 'Content-Type: application/json' \
  --data '{"data":"demo"}'
```

Client 还提供 `POST /crypto/client/request-only`，使用同样的敏感请求体；`POST /crypto/client/response-only` 可使用 `{"data":"demo"}` 请求体。加密演示响应包含实际发送的 STC 请求头、仅含 `ivBase64` 和 `encryptedDataBase64` 的请求密文体、明文和耗时等诊断数据。

响应加密还提供以下异常演示入口，均可使用 `{"data":"demo"}` 或不传请求体，通过 Kong 转发到同名的 `/crypto/server/response-only/...` 接口：

| Client 接口 | 上游响应 |
| --- | --- |
| `POST /crypto/client/response-only/business-exception` | HTTP 200，业务错误码 |
| `POST /crypto/client/response-only/client-exception` | HTTP 400，客户端异常 |
| `POST /crypto/client/response-only/system-exception` | HTTP 500，服务端异常 |

响应加密入口返回 HTTP 200 的诊断结果，原始上游状态记录在 `response.status`，响应密文及解密结果分别位于 `response.cipher`、`response.plain`。明文网关错误直接展示，密文项为 `N/A`；解密失败仍抛出异常，不伪造成功结果。公钥过期仅重试一次，重试后的请求头会反映在诊断结果中。异常接口路径由配置的 `crypto.server.endpoints.response-only` 加对应后缀生成。

明文 Client 接口只有 `POST /plain/client/normal`，接受 `DemoPlainRequest`，通过 `CryptoHttpClient.postPlain` 复用 JSON 请求发送逻辑，不获取公钥、不加解密。成功响应直接返回包含 `request`、`response` 和 `latency in ms` 的 `Map<String, Object>`，其中 `response` 为反序列化后的 `DemoPlainResponse`，耗时结构与 Crypto Client 一致，`encryption`、`decryption` 均为 0，`total`、`http` 为明文调用耗时（毫秒）。此接口及请求加密、双向加密入口遇到上游非 200 响应仍抛出 `HttpStatusException`。Server 对应接口返回 `DemoPlainResponse`。

## Client 配置与 Kong 路由

Client 上游 URL 位于 `client/src/main/resources/application.yml`：

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

`crypto.server` 用于加密调用，`plain.server` 用于明文调用。`PLAIN_SERVER_BASE_URL` 可单独覆盖明文地址；`CRYPTO_SERVER_BASE_URL` 覆盖加密地址，若没有单独覆盖，明文地址也随之变化。Controller 不硬编码上游 URL。

| Kong 路径 | 方法 | Server 目标 | 行为 |
| --- | --- | --- | --- |
| `/crypto/server/public-key` | GET | 无 | 插件从 Vault 读取当前公钥并直接响应 |
| `/crypto/server/bidirectional` | POST | `/crypto/server/bidirectional` | 解密请求并加密响应 |
| `/crypto/server/request-only` | POST | `/crypto/server/request-only` | 解密请求，响应为明文 |
| `/crypto/server/response-only` | POST | `/crypto/server/response-only` | 从请求头解密会话密钥并加密响应 |
| `/plain/server/normal` | POST | `/plain/server/normal` | 无插件，保留路径和明文请求体 |

明文路由使用独立 Kong Service `encryptpii-server-plain`，配置 `strip_path: false`。不要全局挂载加密插件或将插件绑定到该 Service，否则会影响明文链路。修改路径时需同步更新 Client 和 Kong 配置。

## 构建、重部署与镜像导入

Client、Server 和 Kong 的部署脚本都会构建镜像、导入本地 Kubernetes 节点并重启 Deployment。若对应标签的镜像已构建，可使用 `--skip-build`：

```bash
./server/scripts/deploy-to-k8s.sh --skip-build
./client/scripts/deploy-to-k8s.sh --skip-build
./kong/scripts/deploy-to-k8s.sh --skip-build
```

仅构建镜像：

```bash
./server/scripts/build-image.sh
./client/scripts/build-image.sh
./kong/scripts/build-plugin.sh
```

三个组件共用 `scripts/import-local-k8s-images.sh`。该脚本通过临时特权 node-debug Pod 将 Docker 镜像导入 containerd 的 `k8s.io` namespace，并在退出时清理辅助 Pod。清单使用 `imagePullPolicy: Never`；仅在 Docker 中构建镜像并不会自动将其提供给 Kubernetes 节点。重建同一标签的镜像后，需重新导入并重部署。其他集群应使用其支持的镜像导入方式或配置镜像仓库。

## 清理与从头重建

### 删除单个组件

```bash
./client/scripts/delete-from-k8s.sh
./kong/scripts/delete-from-k8s.sh
./server/scripts/delete-from-k8s.sh
./vault/scripts/delete-from-k8s.sh
```

删除脚本要求 `docker-desktop` context，默认要求输入 `DELETE` 确认，可用 `--yes` 跳过交互。脚本保留 namespace 和本地文件。

| 组件 | 默认删除 | 默认保留 |
| --- | --- | --- |
| Client / Server | 自身 Deployment 与 Service | 共享 gateway Secret |
| Kong | Deployment、Service、ConfigMap、ServiceAccount 和 Secret 副本 | Server gateway Secret、Vault 数据 |
| Vault | StatefulSet、Service、ConfigMap、ServiceAccount 和 auth ClusterRoleBinding | PVC、本地凭据 |

Vault 默认保留 PVC；只有确定要永久删除数据时才使用：

```bash
./vault/scripts/delete-from-k8s.sh --purge-data
```

此操作会删除 `data-vault-0` PVC 及关联 PV，Vault 密钥和数据无法恢复。它不会删除本地凭据或修改 `.env`。底层存储的物理擦除不作保证，尤其是 PV 回收策略为 `Retain` 时。

### 清理整个本地部署

```bash
./scripts/cleanup-local-k8s.sh
```

脚本仅删除本项目的 Client、Server、Kong、Vault 具名资源、共享 gateway Secret，以及 Vault PVC `data-vault-0` 和与该 PVC 关联的 PV。保留 `vault`、`kong`、`encryptpii` 三个 namespace、其中的其他资源和本地凭据文件，不按命名空间批量删除资源或 PV。Vault 数据和初始化状态将不可恢复。非交互执行可显式传入 `--yes`：

```bash
./scripts/cleanup-local-k8s.sh --yes
```

不要在这些共享 namespace 中放置无关工作负载。

### 从头重建

确认 `.env` 已正确配置后运行：

```bash
./scripts/rebuild-local-k8s.sh
```

重建脚本会先校验配置（包括 gateway token）并构建 Server、Client、Kong 镜像，再执行有交互确认的清理；配置校验或构建失败时不会先删除现有部署。之后会将旧凭据（包括历史 `gateway-token` 文件）归档到 `vault/.local/previous-*`，初始化新 Vault 和 RSA 密钥，并依次部署 Server、Kong、Client。Gateway token 与单独部署 Server 使用相同来源：已导出的 `KONG_TO_ENCRYPTPII_AUTH_TOKEN` 优先，否则读取根目录 `.env`；不再随机生成 token 或创建 `vault/.local/gateway-token`。Kong 部署时复制 Server 的 gateway Secret，保持两端一致。新的 Vault 凭据保存在 `vault/.local/`；重建会更换 RSA 密钥和 Vault token，旧加密请求与旧 Vault token 不再可用，但不会主动更换 gateway token。

## 密钥与加密协议

Vault KV v2 的每个 RSA 密钥版本包含：

```json
{
  "publicKey": "<Base64 编码的 X.509 SubjectPublicKeyInfo DER>",
  "privateKey": "<Base64 编码的 PKCS#8 私钥 DER>"
}
```

公钥和私钥必须属于同一 RSA-2048 密钥对。KV v2 负责保存版本，不会自动生成或轮换密钥：初始密钥由 Vault 部署脚本创建，后续轮换需显式执行。

| 身份 | Vault 权限 |
| --- | --- |
| Kong Kubernetes auth role | 读取配置路径下的 data 与 metadata |
| 轮换脚本 token | 在既有 data 路径读取和更新 |

例如 `secret/data/sensitive-transport-crypto/rsa-ciam` 对应 metadata 路径 `secret/metadata/sensitive-transport-crypto/rsa-ciam`。建议按应用或安全边界隔离路径和别名。

双向加密和请求加密模式的请求体只包含以下密文。所有加密模式均通过 `X-STC-Key-Id` 和 `X-STC-Session-Key` 请求头传递 keyId 和 RSA-OAEP 加密的 AES 会话密钥：

```json
{
  "ivBase64": "<12-byte IV>",
  "encryptedDataBase64": "<AES-GCM ciphertext followed by the 16-byte authentication tag>"
}
```

RSA 使用 OAEP-SHA-256 和 MGF1-SHA-1，与 Java SDK 默认参数匹配。AES 使用 256-bit GCM、12 字节 IV 和 16 字节认证标签。旧版将 keyId 或加密会话密钥放在请求体中的协议不再支持；出现这些字段或其他额外字段时，Kong 返回 HTTP 400。Kong 转发上游前会移除两个会话头。加密响应包含 `ivBase64` 和 `encryptedDataBase64`。

`KONG_TO_ENCRYPTPII_AUTH_TOKEN` 是独立于 RSA 密钥对的服务间认证密钥，密钥轮换不影响该 token。Server 加密接口在 token 未配置时返回 503，在调用方 token 缺失或不匹配时返回 403。轮换该 token 时，修改 `.env` 后先部署 Server，再部署 Kong，确保两端配置一致。

## 密钥轮换、缓存与过期

手动轮换现有密钥：

```bash
# 读取现有密钥并准备新密钥，但不写入 Vault
./vault/scripts/rotate-vault-key.sh --dry-run

# 创建一个新的 Vault KV v2 版本
./vault/scripts/rotate-vault-key.sh
```

路径默认取自 `.env`，也可作为位置参数传入。脚本默认通过 `kubectl exec` 调用 `vault/vault-0` 内的 Vault CLI，使用 `vault/.local/rotation-token`，无需端口转发。目标密钥必须已存在；脚本保留其他字段，并使用读取到的版本号作为 CAS 条件，避免覆盖并发更新。若 CAS 失败，检查最新版本再决定是否重试。脚本不会显式删除历史版本，但 Vault 保留策略仍可能影响历史版本。

访问外部 Vault 可使用 HTTP API 模式：

```bash
VAULT_ADDR=https://vault.example.invalid VAULT_TOKEN='<rotation-token>' \
  ./vault/scripts/rotate-vault-key.sh --http \
  secret/data/sensitive-transport-crypto/rsa-ciam
```

只有 `--http` 模式需要主机上的 `curl` 和显式 `VAULT_TOKEN`。未显式设置 `VAULT_ADDR` 时，轮换脚本会将 `.env` 中的 `host.docker.internal` 映射到主机 `localhost`；显式设置的地址保持原样，主机无法直接解析集群 Service DNS。临时密钥文件权限受限，并在脚本退出时清理；脚本不会打印密钥或 token。

时间计算：

```text
公钥到期时间 = Vault 版本 created_time + key_validity_millis
历史版本解密截止时间 = 轮换时刻 + key_grace_period_millis
```

当前公钥过期后，公钥接口返回 HTTP 503；宽限期仅允许解密历史密钥，不会延长已过期公钥的签发时间。部署 Kong 或重新应用路由不会重置 Vault 的 `created_time`。无自动轮换调度任务；应在到期前安排轮换、监控失败并协调客户端刷新、宽限期与 Vault 版本保留。

Kong 公钥接口每次从 Vault 读取当前版本并设置 `Cache-Control: no-store`，不会返回私钥；轮换后无需重启 Kong。Client 仍可能在其公钥缓存有效期内发送旧 `keyId`。Kong 每个 worker 最多缓存解析后的私钥 60 秒，且受密钥截止时间约束；缓存不是即时撤销机制，空闲 worker 的过期条目会在后续私钥访问时清理。

若请求引用的 `keyId` 不存在或超过宽限期，Kong 返回 HTTP 400、`code: "KEY_EXPIRED"`，并在 `data` 中附上最新公钥。Java Client 会安装新公钥、重新加密并最多重试一次，无需额外先请求公钥。别名不匹配返回 `code: "INVALID_KEY"`，不附带新公钥，也不重试；格式错误或解密失败不是刷新信号。

## 外部 Vault 迁移

`vault/scripts/initialize-and-migrate.sh` 可将外部 KV v2 中的历史密钥版本迁移至本地 Vault。需在 `.env` 设置目标密钥路径，并为来源 Vault 提供地址和只读 token：

```bash
SOURCE_VAULT_ADDR=https://source-vault.example.invalid \
SOURCE_VAULT_TOKEN='<source-token>' \
  ./vault/scripts/initialize-and-migrate.sh
```

脚本不修改来源 Vault。目标 Vault 必须尚未启用 `secret/` mount，以避免覆盖已有迁移或数据。若来源版本含已删除或销毁版本，脚本会停止，避免迁移后静默改变版本标识。迁移后的版本号和创建时间会重新生成；切换运行环境前需评估客户端 `keyId`、宽限期和版本切换安排。

## 运维与故障排查

检查状态和日志：

```bash
kubectl -n vault get pods,svc,pvc
kubectl -n kong get pods,svc
kubectl -n encryptpii get pods,svc
kubectl -n kong logs deployment/encryptpii-kong
kubectl -n encryptpii logs deployment/encryptpii-server
kubectl -n encryptpii logs deployment/encryptpii-client
```

Vault 使用手动解封。Pod 重启后如处于 sealed 状态：

```bash
./vault/scripts/unseal.sh
```

不要将删除 PVC 或本地凭据当作常规维护。PVC 不能防止本地集群或底层存储丢失，应另行安排备份。

需要检查 Kong 时，可在单独终端执行：

```bash
kubectl -n kong port-forward service/encryptpii-kong 18443:8443 18000:8000 18001:8001 18002:8002
curl --cacert certs/kong.crt --fail-with-body https://localhost:18443/crypto/server/public-key
```

本机端口 `18443`、`18000`、`18001`、`18002` 分别对应 Kong HTTPS Proxy、HTTP Proxy、Admin API 和 Manager。Manager 页面访问时应保持浏览器 host 一致，混用 `localhost` 与 `127.0.0.1` 可能导致 CORS 错误。Vault UI/API 诊断可选用：

```bash
kubectl -n vault port-forward service/vault 18200:8200
```

| 现象 | 排查方向 |
| --- | --- |
| 公钥接口返回 503 | 检查 Vault 是否解封、token 权限、data/metadata 路径、RSA 字段和公钥是否过期，并查看 Kong 日志 |
| 业务调用返回 403 | 检查 Server 与 Kong 的 gateway Secret 是否一致，确认没有直接调用受保护的 Server 接口 |
| 业务错误响应为密文 | 解密响应并查看 Server 日志；上游错误也可能被 Kong 加密 |
| 轮换后 Client 仍使用旧 `keyId` | Client 可能缓存尚未过期的公钥；如需立即刷新，重启 Client |
| 本机 `18080` 无法访问 | 检查 LoadBalancer 是否就绪和本机端口冲突，确认没有旧端口转发占用 |
| Kubernetes 找不到本地镜像 | 将镜像导入节点运行时；仅执行 Docker build 不足以供集群使用 |
| 主机无法解析集群 Service DNS | 通过 Client LoadBalancer 或显式端口转发访问 |
| DB-less Kong 拒绝 Admin API 配置写入 | 重新运行 `kong/scripts/deploy-to-k8s.sh`，不要运行 `configure-routes.sh` |
| Vault 部署与凭据不匹配 | 恢复与该 PVC 对应的凭据；不要覆盖初始化文件或丢弃数据 |
