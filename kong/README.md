# Kong 加密网关

本目录提供 Kong Gateway 插件 `sensitive-transport-crypto`，用于在客户端与 Spring Server 之间执行请求解密、响应加密，并从 Vault KV v2 读取 RSA 密钥。Kong 负责密钥读取与加解密；Server 只接收经过网关授权的明文业务请求。

当前推荐使用 Kubernetes 部署。部署清单以 Kong 3.7、DB-less 模式和 Kubernetes ServiceAccount 身份访问 Vault 为准。Docker Compose 文件仅用于构建插件镜像，不支持独立运行时部署。

## 目录结构

| 路径 | 用途 |
| --- | --- |
| `plugins/sensitive-transport-crypto/` | `handler.lua` 生命周期编排；`vault.lua` Vault Kubernetes 登录与 token 缓存；`keys.lua` 密钥读取、有效期校验与私钥缓存；`crypto.lua` RSA/AES-GCM 加解密；`schema.lua` 配置 schema |
| `k8s/kong.yaml` | Kong Namespace、ServiceAccount、Deployment 和 Service |
| `scripts/build-plugin.sh` | 构建镜像、检查 Lua 文件并运行插件测试 |
| `scripts/deploy-to-k8s.sh` | 生成 DB-less 配置并部署 Kong |
| `scripts/install-to-kong.sh` | 部署脚本的兼容入口 |
| `scripts/configure-routes.sh` | 为数据库模式的 Kong 配置路由和插件 |
| `scripts/delete-from-k8s.sh` | 删除 Kubernetes 中的 Kong |
| `Dockerfile`、`docker-compose.yml` | Kong 插件镜像构建配置 |

部署和配置脚本从仓库根目录读取 `.env`。环境变量优先于 `.env` 中的同名配置；`.env` 只解析字面量 `KEY=value`，不会执行 shell 命令或变量展开。

## 请求处理

插件支持三种业务路由：

| 客户端路径 | 方法 | 处理方式 |
| --- | --- | --- |
| `/crypto/server/bidirectional` | POST | 从请求头解密会话密钥、解密请求体，转发明文请求，并使用同一会话密钥加密响应 |
| `/crypto/server/request-only` | POST | 从请求头解密会话密钥、解密请求体后转发明文响应 |
| `/crypto/server/response-only` | POST | 从请求头解密会话密钥，转发请求，并加密响应 |
| `/crypto/server/response-only/client-exception` | POST | 独立响应加密路由，转发到客户端异常接口（HTTP 400） |
| `/crypto/server/response-only/system-exception` | POST | 独立响应加密路由，转发到系统异常接口（HTTP 500） |
| `/crypto/server/response-only/business-exception` | POST | 独立响应加密路由，转发到业务异常接口（HTTP 200） |
| `/crypto/server/public-key` | GET | Kong 从 Vault 获取当前公钥并直接响应，不转发到 Server |
| `/plain/server/normal` | POST | 演示用明文路由；不挂载插件，保留路径转发到 Server |

三个异常路由均配置 `decrypt_request=false`、`encrypt_response=true`，其
`upstream_path` 分别指向对应异常接口。
更长的子路径优先匹配，避免落入普通响应加密路由后被改写为 `/crypto/server/response-only`。

所有加密模式均从 `X-STC-KEY-ID` 和 `X-STC-SESSION-KEY` 请求头读取密钥标识与 RSA 加密的会话密钥。请求加密模式的请求体只包含：

```json
{
  "ivBase64": "<12-byte IV>",
  "encryptedDataBase64": "<AES-GCM ciphertext followed by the 16-byte tag>"
}
```

RSA 使用 OAEP-SHA-256，MGF1 使用 SHA-1，以匹配 Java SDK 的 `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` 默认参数。会话密钥为 256-bit AES，数据采用 GCM，IV 为 12 字节、认证标签为 16 字节。响应体包含 `ivBase64` 和 `encryptedDataBase64`。

双向加密、请求加密和响应加密均要求这两个请求头。Kong 在所有加密路由转发上游前移除它们，并注入 `X-Crypto-Gateway-Token`。请求体中出现旧版 `keyId` 或 `encryptedSessionKeyBase64` 字段、或其他非协议字段时会明确返回 HTTP 400；不支持 body/header 混用或回退。Server 必须配置相同的 `KONG_TO_ENCRYPTPII_AUTH_TOKEN`，且不能将受保护的内部明文接口直接暴露给不可信网络。

## Vault 密钥与轮换

Vault KV v2 中每个版本应包含 Base64 编码的 X.509 公钥 DER 和 PKCS#8 私钥 DER，字段名分别为 `publicKey` 和 `privateKey`。SDK、Kong 与 Server 的密钥别名和 Vault 路径必须一致。客户端使用 `<keyAlias>:<version>` 作为 `keyId`。

插件使用 Kong Pod 的 ServiceAccount JWT 登录 Vault Kubernetes auth，不在 Kubernetes Secret 中保存 Vault token。Vault 返回的短期 token 会在 Kong worker 内缓存；解析后的私钥也按 worker 缓存，最多缓存 60 秒，并受密钥有效期和宽限期约束。缓存过期清理在后续私钥访问时触发，不运行定时清理任务；移除缓存引用不代表内存内容已立即安全擦除。插件不会删除 Vault 中的密钥版本。

当前版本在 `key_validity_millis` 有效期内可用；版本轮换后，旧版本根据 Vault KV v2 元数据中的下一版本 `created_time` 计算轮换时刻，并仅在 `key_grace_period_millis` 内继续接受。保留旧版本及其元数据至少覆盖客户端缓存与宽限期所需时间。

请求引用不存在、不可用或已超过宽限期的版本时，网关返回 HTTP 400、`code: "KEY_EXPIRED"`，并附带最新公钥，客户端可刷新公钥后重试一次。响应示例：

```json
{
  "code": "KEY_EXPIRED",
  "msg": "密钥版本已过期，请更新公钥。最新公钥参考data",
  "data": {
    "publicKeyBase64": "xxxxx",
    "keyId": "rsa-ciam:2",
    "expiresAtEpochMillis": 1735689600000
  }
}
```

密钥别名不匹配返回 `code: "INVALID_KEY"`，不附带公钥数据。不要把其他校验或解密错误当作密钥过期并自动重试。无法从 Vault 获取当前公钥时，公钥接口或过期密钥响应会返回 HTTP 503。

以下时间线说明旧版本宽限期与客户端公钥缓存可能不同步的情况：

| 时间 | 事件 | 说明 |
| --- | --- | --- |
| 08:19:57 | 推算版本 15 创建 | 示例中的公钥到期时间为 08:20:57，减去 60 秒有效期 |
| 08:20:19 | 推算版本 16 创建并完成轮换 | 版本 16 示例到期时间为 08:21:19，减去 60 秒有效期 |
| 08:20:30 | 使用版本 15 的请求成功 | 仍处于轮换后的宽限期 |
| 08:20:49 | 版本 15 的宽限期结束 | 轮换时刻 08:20:19 加 30 秒宽限期 |
| 08:20:55 | 版本 15 被拒绝，刷新版本 16 后重试成功 | 即使客户端缓存尚未过期，旧版本超过宽限期也会返回 `KEY_EXPIRED` |
| 08:21:25 | 版本 16 的公钥缓存过期，刷新返回 503 | 客户端刷新失败，因此不会发送使用版本 16 加密的业务请求 |

## 部署到 Kubernetes

部署前准备：

- Kubernetes 当前 context 为 `docker-desktop`；当前部署脚本会检查该 context。
- Vault 和 Server 已部署，且 Vault KV v2 密钥已创建。
- Vault Kubernetes auth role `encryptpii-kong` 已绑定 `kong/encryptpii-kong` ServiceAccount。
- 该 role 仅有目标 KV v2 路径的读取权限，包括对应的 `secret/data/...` 和 `secret/metadata/...` 路径。
- `encryptpii` namespace 中已存在 `encryptpii-gateway` Secret，包含 Server 使用的 `token` key。
- 已安装 Docker Compose、`kubectl`、`jq` 和 Bash；本地镜像导入脚本可用。

在仓库根目录创建并填写 `.env`：

```bash
cp .env.example .env
```

至少设置以下加密配置，并将共享随机 token 配置给 Kong 与 Spring Server：

```dotenv
KONG_TO_ENCRYPTPII_AUTH_TOKEN=replace-with-a-random-shared-secret
KONG_TLS_CERT_FILE=certs/kong.crt
KONG_TLS_KEY_FILE=certs/kong.key
ENCRYPTPII_VAULT_SECRET_PATH=secret/data/sensitive-transport-crypto/rsa-ciam
ENCRYPTPII_KEY_ALIAS=rsa-ciam
ENCRYPTPII_KEY_VALIDITY_MILLIS=3600000
ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS=600000
ENCRYPTPII_MAX_BODY_BYTES=1048576
```

`KONG_TLS_CERT_FILE` 和 `KONG_TLS_KEY_FILE` 是相对仓库根目录或绝对路径的 PEM 文件路径。证书必须包含客户端访问 Kong 时使用的 DNS 名称或 IP 地址；不要将证书私钥提交到 Git。部署脚本会在 `kong` namespace 创建或更新 `encryptpii-kong-tls` Secret，并挂载到 Kong。部署前需准备证书，例如本机端口转发测试可使用自签名 localhost 证书：

```bash
./scripts/create-kong-certificate.sh
```

脚本生成 `certs/kong.crt` 和 `certs/kong.key`，有效期 365 天，SAN 包含 `localhost` 和 `local.kong.test`，私钥权限为 `600`。默认拒绝覆盖已有文件；确认需要重新签发时添加 `--force`。证书更换后需更新 Kong TLS Secret 并重启 Kong，客户端信任配置也需按需更新。

若 `.env` 配置为默认的 `certs/kong.crt` 和 `certs/kong.key`，且两个文件均不存在，`deploy-to-k8s.sh` 会自动调用上述脚本生成证书，再写入 TLS Secret。已有证书不会被重新签发；仅缺少其中一个文件或自定义路径下文件缺失时，部署会报错，不会自动覆盖或生成。`install-to-kong.sh` 也使用同一部署流程。

本机访问时将代理 HTTPS 端口转发到 `18443`：

```bash
kubectl -n kong port-forward service/encryptpii-kong 18443:8443
curl --cacert certs/kong.crt https://localhost:18443/crypto/server/public-key
```

生产环境应使用受信任 CA 签发且 SAN 与实际域名匹配的证书，并通过安全的证书管理流程更新证书后重新部署 Kong。HTTP 代理端口 `8000` 仍然开放；如需强制 HTTPS，应在入口层禁用 HTTP 或配置 HTTP 到 HTTPS 重定向。Admin API 不应向不可信网络开放。

部署 Kong：

```bash
./kong/scripts/deploy-to-k8s.sh
```

该脚本会构建镜像（除非指定 `--skip-build`）、从 Server namespace 复制 `encryptpii-gateway` Secret、生成 DB-less 路由配置并部署 Kong。安装入口等价：

```bash
./kong/scripts/install-to-kong.sh
```

构建并运行插件 Lua 与密钥缓存测试：

```bash
./kong/scripts/build-plugin.sh
```

如需本机访问本地集群中的 Kong：

```bash
kubectl -n kong port-forward service/encryptpii-kong 18443:8443 18000:8000 18001:8001 18002:8002
```

Kong 的 HTTPS 代理、HTTP 代理、Admin API 和 Manager 分别通过本机端口 `18443`、`18000`、`18001` 和 `18002` 访问。Admin API 不应向不可信网络开放。

## 路由与配置

Kubernetes 部署脚本生成的 DB-less 配置包含上述加密路由和独立明文路由。明文演示路由仅用于本地演示：它绑定独立的 `encryptpii-server-plain` Service，不挂载加密插件，且以 `strip_path: false` 保留 `/plain/server/normal` 路径。不要将插件配置为全局插件或绑定到明文 Service。

`configure-routes.sh` 适用于数据库模式下、可访问 Kong Admin API 的部署；它会幂等配置一个上游服务、四条加密路由及对应插件，并配置明文路由。它不用于当前 DB-less Kubernetes 部署。脚本需要 `.env` 中的 `KONG_ADMIN_URL`、`ENCRYPTPII_UPSTREAM_URL`、Vault 地址和密钥配置：

```bash
./kong/scripts/configure-routes.sh
```

插件配置示例（密钥引用应由部署环境安全提供）：

```yaml
plugins:
  - name: sensitive-transport-crypto
    route: encrypted-api
    config:
      vault_addr: http://vault.vault.svc.cluster.local:8200
      vault_auth_role: encryptpii-kong
      vault_kubernetes_jwt_path: /var/run/secrets/kubernetes.io/serviceaccount/token
      vault_secret_path: secret/data/sensitive-transport-crypto/rsa-ciam
      key_alias: rsa-ciam
      key_validity_millis: 3600000
      key_grace_period_millis: 600000
      upstream_path: /crypto/server/bidirectional
      upstream_auth_token: "{vault://env/KONG_TO_ENCRYPTPII_AUTH_TOKEN}"
      decrypt_request: true
      encrypt_response: true
      max_body_bytes: 1048576
```

请求解密单向路由使用 `decrypt_request: true`、`encrypt_response: false`；仅响应加密路由使用 `decrypt_request: false`、`encrypt_response: true`。所有这类加密路由都从固定的两个 STC 请求头读取会话材料。公钥路由使用 `serve_public_key: true`，由插件直接返回 Vault 中的当前公钥、`keyId` 和 `expiresAtEpochMillis`。

主要配置项：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `vault_addr` | 必填 | Vault HTTP(S) 地址 |
| `vault_auth_role` | 必填 | Kubernetes auth role |
| `vault_kubernetes_jwt_path` | ServiceAccount 标准路径 | Pod 内 JWT 文件路径 |
| `vault_secret_path` | 必填 | KV v2 data 路径，例如 `secret/data/...` |
| `key_alias` | 必填 | SDK 使用的密钥别名 |
| `key_validity_millis` | `60000` | 当前密钥有效期 |
| `key_grace_period_millis` | `30000` | 密钥轮换后的旧版本宽限期 |
| `upstream_path` | 必填 | 转发到上游的路径 |
| `upstream_auth_token` | 必填 | 上游共享认证 token，可使用 Kong Vault 引用 |
| `decrypt_request` | `false` | 是否解密请求体 |
| `encrypt_response` | `false` | 是否加密响应体 |
| `serve_public_key` | `false` | 是否由 Kong 直接提供公钥 |
| `max_body_bytes` | `1048576` | 请求/响应加解密缓冲上限，最大 16 MiB |

## 手动轮换密钥

仓库提供的一次性轮换脚本会在现有 Vault KV v2 路径新增 RSA-2048 密钥版本，保留其他字段和历史版本，并通过 CAS 避免并发覆盖。先执行 dry run，再确认后轮换：

```bash
./vault/scripts/rotate-vault-key.sh --dry-run secret/data/sensitive-transport-crypto/rsa-ciam
./vault/scripts/rotate-vault-key.sh secret/data/sensitive-transport-crypto/rsa-ciam
```

脚本默认通过 `kubectl exec` 在 `docker-desktop` context 的 Vault 中操作，使用 `vault/.local/rotation-token` 或显式设置的 `VAULT_TOKEN`，不需要端口转发。轮换 token 应单独创建，并仅授予目标 data 路径的 `read` 和 `update` 权限；不要复用 Kong 的只读 Kubernetes auth role。访问外部 Vault 时使用 `--http`；`VAULT_ADDR` 和 `VAULT_TOKEN` 可覆盖 `.env` 配置。若 CAS 失败，先检查 Vault 当前版本，再决定是否重新执行。轮换不是自动调度任务。

## 运维与安全

- 插件需要缓冲请求体和响应体；`max_body_bytes` 默认 1 MiB、最大 16 MiB。Kong Nginx 请求体上限也设置为 16 MiB。
- 转换响应前，插件要求上游使用 identity encoding，并清理压缩相关响应头。
- 超过大小限制的请求返回 HTTP 413；无效请求或解密失败返回 HTTP 400；响应加密失败返回 HTTP 502。
- 插件会接触解密后的业务数据。客户端到 Kong 及生产环境 Kong 到 Vault 的连接应使用 TLS；不要把请求/响应明文写入日志、追踪或诊断信息。
- `KONG_TO_ENCRYPTPII_AUTH_TOKEN` 必须在 Kong 与 Spring Server 中配置为相同值。修改共享 token 后，应先更新并重启 Server，再重新部署 Kong。
- 修改 Vault 路径、别名或其他 DB-less 路由配置后，重新运行 `deploy-to-k8s.sh`。轮换密钥无需将私钥写入 Kong 配置或 Kubernetes Secret。
- Kong 插件使用 `lua-resty-openssl`、`resty.http` 和 LuaJIT；部署其他 Kong 版本时，应验证基础镜像及其依赖兼容性。
