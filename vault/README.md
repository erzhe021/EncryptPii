# Vault

本目录提供本地 Kubernetes Vault 部署，以及 EncryptPii RSA 密钥的初始化、访问控制和轮换脚本。当前配置面向仓库的本地 `docker-desktop` 集群，不应直接作为生产环境配置使用。

## 文件说明

| 路径 | 用途 |
| --- | --- |
| `k8s/vault.yaml` | Vault StatefulSet、Raft 持久存储、Service、ServiceAccount 和 Kubernetes auth 所需 RBAC |
| `scripts/deploy-to-k8s.sh` | 部署 Vault；首次初始化 Vault、KV v2 和应用所需的 Vault policy/auth role |
| `scripts/unseal.sh` | 使用本地初始化凭据解封 Vault |
| `scripts/rotate-vault-key.sh` | 在已有 KV v2 密钥路径创建新的 RSA-2048 密钥版本 |
| `scripts/initialize-and-migrate.sh` | 将外部 Vault 的 KV v2 历史密钥版本迁移到本地 Vault |
| `scripts/delete-from-k8s.sh` | 删除 Vault Kubernetes 资源；可选永久删除持久化数据 |
| `scripts/common.sh` | 部署与轮换脚本共用的 Vault 命令辅助函数 |
| `.local/` | 本地初始化凭据与受限用途的 token；已加入 Git 忽略，不应提交或公开 |

脚本从仓库根目录读取 `.env`。Vault 部署至少需要有效的 `ENCRYPTPII_VAULT_SECRET_PATH`，路径格式为 KV v2 的 `secret/data/...`，并使用 `.env.example` 中的 `ENCRYPTPII_VAULT_ADDR` 等 EncryptPii 配置。需要 `kubectl`、`jq`、`openssl` 和 Bash；迁移及 HTTP 轮换还需要 `curl`。

## 部署与初始化

先在仓库根目录创建 `.env` 并填写配置：

```bash
cp .env.example .env
```

将密钥路径和别名设为与 SDK、Kong、Server 相同的值，例如：

```dotenv
ENCRYPTPII_VAULT_ADDR=http://vault.vault.svc.cluster.local:8200
ENCRYPTPII_VAULT_SECRET_PATH=secret/data/sensitive-transport-crypto/rsa-ciam
ENCRYPTPII_KEY_ALIAS=rsa-ciam
```

部署：

```bash
./vault/scripts/deploy-to-k8s.sh
```

脚本要求当前 Kubernetes context 为 `docker-desktop`。首次运行会创建 `vault` namespace 和 StatefulSet；等待 Vault 启动后，以 1 个 key share、1 个 threshold 初始化，并将初始化结果保存在 `vault/.local/init.json`。随后脚本解封 Vault、启用 KV v2 `secret/` mount，在配置的密钥路径创建初始 RSA-2048 密钥，并配置 Kong 与轮换所需的 policy 和 Kubernetes auth role。

重复运行会保留已有 Vault 数据和当前密钥版本，不会自动轮换密钥。若 Vault 是已初始化的实例，必须提供与该实例匹配的 `vault/.local/init.json`；脚本不会覆盖已有初始化文件，也不会用新凭据接管现有 Vault。

部署成功后，脚本在 `.local/` 保存 Vault 初始化凭据及轮换 token，并在 Kubernetes 配置只读的 `encryptpii-kong` Kubernetes auth role。Kong 通过 `kong/encryptpii-kong` ServiceAccount 取得短期 Vault token，不依赖静态 Vault token Secret。部署 Server 和 Kong 时，应使用相同的 Vault 路径及密钥别名。

## 密钥格式与权限

Vault 中的每个 KV v2 密钥版本包含两个字段：

| 字段 | 内容 |
| --- | --- |
| `publicKey` | Base64 编码的 X.509 SubjectPublicKeyInfo DER |
| `privateKey` | Base64 编码的 PKCS#8 DER |

初始密钥由部署脚本生成；之后可使用轮换脚本新增密钥版本。Kong 读取指定版本的私钥和版本元数据，并读取当前版本的公钥。部署脚本生成的 `encryptpii-kong-k8s` policy 只允许读取配置路径下的 data 与 metadata；专用 `encryptpii-rotation` policy 允许读取和更新密钥 data 路径。不要将 Vault 管理员凭据提供给 Kong。

`.local/init.json` 包含解封材料和 root token，`.local/rotation-token` 是可更新密钥的长期 token。应限制本地文件访问、将其安全备份到受控凭据存储，并在凭据泄露时按 Vault 操作流程轮换或撤销。不要将这些文件复制到工单、日志、聊天记录或版本控制中。

## 轮换密钥

先检查将要写入的变更：

```bash
./vault/scripts/rotate-vault-key.sh --dry-run
```

dry run 会读取当前密钥并生成临时 RSA-2048 密钥以验证写入数据，但不会创建 Vault 新版本。确认后执行：

```bash
./vault/scripts/rotate-vault-key.sh
```

默认路径从根目录 `.env` 的 `ENCRYPTPII_VAULT_SECRET_PATH` 读取，也可显式指定 KV v2 data 路径：

```bash
./vault/scripts/rotate-vault-key.sh secret/data/sensitive-transport-crypto/rsa-ciam
```

默认通过 `kubectl exec` 访问 `docker-desktop` 集群中的 `vault/vault-0`，不需要端口转发。脚本默认使用 `.local/rotation-token`，也可用 `VAULT_TOKEN` 显式覆盖。写入时保留当前密钥对象中的其他字段，并使用当前版本号作为 CAS 条件，拒绝覆盖并发写入产生的新版本。该命令是一次性轮换，不会配置定时任务。

访问外部 Vault 时可使用 HTTP API 模式：

```bash
VAULT_ADDR=https://vault.example.invalid VAULT_TOKEN='<rotation-token>' \
  ./vault/scripts/rotate-vault-key.sh --http
```

HTTP 模式必须提供 `VAULT_TOKEN`；地址可由 `VAULT_ADDR` 覆盖根目录 `.env` 的 `ENCRYPTPII_VAULT_ADDR`。生产环境应使用经过验证的 HTTPS 连接。轮换 token 应独立管理，并仅授予目标 KV v2 data 路径所需的 `read`、`update` 权限。

轮换后，新公钥由 Kong 的公钥端点提供。旧版本是否仍可解密取决于 Kong 配置的宽限期；在宽限期内应保留旧 KV 版本及其 metadata。不要提前删除或销毁 SDK、Kong 仍可能使用的版本。

## 从外部 Vault 迁移

`initialize-and-migrate.sh` 会从外部 KV v2 Vault 逐版本读取配置路径下的密钥，并按版本顺序写入新部署的本地 Vault。它要求根目录 `.env` 配置目标路径，并通过环境变量提供来源 Vault 地址与 token：

```bash
SOURCE_VAULT_ADDR=https://source-vault.example.invalid \
SOURCE_VAULT_TOKEN='<source-token>' \
  ./vault/scripts/initialize-and-migrate.sh
```

脚本不会修改来源 Vault；目标必须是尚无 `secret/` mount 的 Vault，以免覆盖已有迁移或数据。若来源版本包含已删除或销毁版本，脚本会停止，避免在迁移后悄悄改变版本标识。迁移后的版本号和创建时间会重新生成，因此需要评估客户端 key id、轮换宽限期和运行环境切换安排。迁移 token 应具备读取来源路径及其 metadata 的最小权限。

## 解封、访问与删除

若 Vault Pod 重启后处于 sealed 状态，可运行：

```bash
./vault/scripts/unseal.sh
```

该脚本从 `vault/.local/init.json` 读取解封密钥并通过 `kubectl exec` 解封 `vault/vault-0`。不要把解封密钥作为命令行参数传递或输出到日志。

Vault Service 仅在集群内提供 API；本地临时调试可使用端口转发：

```bash
kubectl -n vault port-forward service/vault 8200:8200
```

删除组件前应确认 Kubernetes context 为 `docker-desktop`。默认删除只移除 Vault 工作负载和相关集群资源，保留 PVC 与本地凭据，以便之后恢复：

```bash
./vault/scripts/delete-from-k8s.sh
```

脚本会要求输入 `DELETE` 确认；非交互自动化可显式传入 `--yes`。只有确定永久销毁 Vault 数据时才使用：

```bash
./vault/scripts/delete-from-k8s.sh --purge-data
```

`--purge-data` 会删除 Vault PVC 及其关联 PV，密钥和数据无法恢复。删除后再次初始化前，应先安全归档或处置 `.local/` 中旧的初始化凭据和 token；不要将旧凭据误用于新的 Vault 实例。

## 部署限制

当前 manifest 使用单副本 StatefulSet 和 1 GiB PVC，Raft 数据存储在该 PVC；Vault listener 的 TLS 被关闭，适用于隔离的本地集群，不构成高可用或生产安全配置。生产部署需另行设计 TLS、自动解封、备份与恢复、访问审计、可靠的存储和高可用，并限制 Vault 与 Kong Admin API 的网络访问。
