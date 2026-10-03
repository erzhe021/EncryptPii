# 本地 Kubernetes 从零部署指南

本指南假定代码仓库已经检出，只有一个可用的本地 Kubernetes 集群；不依赖预先运行的 Vault、Kong 或业务服务。下面的镜像导入和 Kong 部署脚本面向 Docker Desktop Kubernetes，并要求当前 `kubectl` context 为 `docker-desktop`。Vault 使用单节点 Raft、单份解封密钥和未启用 TLS 的 HTTP，仅适用于本地演示。

部署完成后，Java 客户端在集群内访问 Kong Service；Kong 从 Vault KV v2 读取密钥、解密请求并加密响应，再把明文请求转发给 Spring Server。主机只需转发 Client Service 即可调用演示接口。

## 一键清理与重建

根目录 `scripts/` 中的清理和重建入口负责流程编排，调用各组件的独立删除、构建和部署脚本。组件资源的删除逻辑共享于 `scripts/lib/`，镜像导入仍由公共脚本负责，避免重复实现。全量清理调用组件删除后仍会删除项目命名空间及残留资源；重建在清理前调用组件构建脚本，构建失败不会先删除现有部署。

Client、Server 和 Kong 部署支持 `--skip-build`，仅用于复用已经构建的本地镜像；全量重建自动使用该选项，不再重复构建。Kong 配置会在清理前按插件 schema 校验有效期、宽限期和请求体上限。Vault 部署会检查现有活动密钥未被删除/销毁且 RSA 公私钥匹配；Vault 部署和迁移共享策略、令牌及 Secret 发布逻辑。迁移在写入历史版本之前配置足够的版本保留数量，避免默认 10 个版本限制导致历史数据丢失。

各组件也提供独立部署入口，下面按依赖顺序执行（需先安装工具并配置根目录 `.env`）：

```bash
./vault/scripts/deploy-to-k8s.sh
./server/scripts/deploy-to-k8s.sh
./sensitive-transport-crypto/scripts/deploy-to-k8s.sh
./client/scripts/deploy-to-k8s.sh
```

脚本通过自身路径定位仓库，不要求当前工作目录为根目录。Client、Server、Kong 会构建和导入本地镜像并重启对应 Deployment；Server 保留已有 gateway Secret，首次部署从 `.env` 创建它。Vault 首次自动初始化、解封、创建 RSA 密钥及 Kong/轮换令牌，重复执行不会主动轮换已有密钥，也不会删除 PVC。Vault 自动管理需要保留与当前实例匹配的 `vault/.local/init.json`；令牌失效会明确报错，不会静默替换。已有密钥过期时仍需单独执行轮换脚本。

各组件也提供独立删除入口，建议按下面的顺序停止整条链路：

```bash
./client/scripts/delete-from-k8s.sh
./sensitive-transport-crypto/scripts/delete-from-k8s.sh
./server/scripts/delete-from-k8s.sh
./vault/scripts/delete-from-k8s.sh
```

所有删除脚本均要求 `docker-desktop` context，默认输入 `DELETE` 确认，支持 `--yes` 跳过确认，并保留命名空间。Client 和 Server 只删除自身 Deployment/Service，保留共享 gateway Secret；Kong 删除自身 Deployment/Service、配置 ConfigMap 和两个 Secret 副本，不影响 Server 的 gateway Secret。

Vault 默认仅删除 StatefulSet、Service 和 ConfigMap，保留 PVC、Kong 中的 Vault token Secret 及本地凭据；重新运行 Vault 独立部署脚本即可恢复。如果确实需要删除 Vault 的持久数据：

```bash
./vault/scripts/delete-from-k8s.sh --purge-data
```

该选项额外删除 `vault/data-vault-0` PVC、关联 PV 和 `kong/encryptpii-vault` Secret，密钥及数据不可恢复。它不删除本地凭据或修改 `.env`；再次初始化前需安全归档旧的 `vault/.local/init.json`、`kong-token*` 和 `rotation-token*` 文件。对于采用 `Retain` 策略的存储，删除 PV 对象不等于擦除底层磁盘。

仓库根目录提供清理和重建脚本。清理脚本只允许在 `docker-desktop` context 下执行，并删除 `vault`、`kong`、`encryptpii` 三个命名空间中的全部资源，以及 Vault 命名空间关联的 PersistentVolume：

```bash
./scripts/cleanup-local-k8s.sh
```

交互提示要求输入 `DELETE` 才会继续。也可以显式使用 `--yes` 跳过确认：

```bash
./scripts/cleanup-local-k8s.sh --yes
```

这会删除 Vault PVC 中的全部数据，包括密钥、初始化状态和本地集群内的令牌；此操作无法撤销。删除 Kubernetes PersistentVolume 对象不保证清除外部存储系统中采用 `Retain` 回收策略的底层磁盘。

彻底重建时，先按下文安装工具，并配置仓库根目录 `.env` 中的 `ENCRYPTPII_VAULT_SECRET_PATH` 和 `ENCRYPTPII_KEY_ALIAS`，然后运行：

```bash
./scripts/rebuild-local-k8s.sh
```

重建脚本会先构建 Server、Client 和 Kong 镜像；构建成功后再调用清理脚本（仍需输入 `DELETE`），重新初始化 Vault、创建 KV v2 密钥和最小权限 token、生成新的 gateway token、导入本地镜像并部署 Vault、Server、Kong、Client。旧的 `vault/.local` 初始化凭据及 token 会保留在新的 `vault/.local/previous-*` 备份目录中；新凭据仍放在 `vault/.local/`。脚本结束后使用 Client Service 的端口转发访问接口。该操作会更换 Vault 密钥和 gateway token，之前加密的数据或正在使用旧 token 的客户端不再适用。

## 1. 安装本地工具并检查集群

macOS 可用 Homebrew 安装本指南所需的工具：

```bash
brew install kubectl jq
brew install --cask docker temurin@17
```

启动 Docker Desktop，确认 Kubernetes 已启用且集群处于运行状态。安装完成后，在仓库根目录执行：

```bash
docker version
docker compose version
kubectl config current-context
kubectl get nodes
java -version
```

`kubectl config current-context` 必须显示 `docker-desktop`，节点应为 `Ready`。如果你的本地集群不是 Docker Desktop，仓库现有的 Kong 部署脚本会拒绝执行；需要先调整脚本中的节点镜像导入步骤。仓库 Gradle Wrapper 会按需下载 Gradle。

## 2. 部署并初始化全新的 Vault

先创建 Vault StatefulSet 和持久卷：

```bash
kubectl apply -f vault/k8s/vault.yaml
kubectl -n vault wait --for=jsonpath='{.status.phase}'=Running pod/vault-0 --timeout=180s
```

首次启动时 Vault 尚未初始化，Pod 暂时不会 Ready，这是正常的。初始化密钥和 root token 必须妥善保管：

```bash
umask 077
mkdir -p vault/.local
kubectl -n vault exec vault-0 -- vault operator init \
  -key-shares=1 -key-threshold=1 -format=json > vault/.local/init.json
chmod 600 vault/.local/init.json
./vault/scripts/unseal.sh
```

`vault/.local/` 已加入 Git 忽略规则。请将其中的初始化凭据安全备份到仓库之外；不要提交或分享，也不要删除 Vault PVC。该演示配置只有一份解封密钥，丢失初始化凭据可能导致无法恢复数据。

创建 KV v2 挂载点和一个临时占位 secret。密钥轮换脚本要求目标 secret 已存在，之后会把真实 RSA 密钥写为新版本：

```bash
{
  jq -er '.root_token' vault/.local/init.json
} | kubectl -n vault exec -i vault-0 -- sh -c '
  IFS= read -r VAULT_TOKEN
  export VAULT_TOKEN
  vault secrets enable -path=secret kv-v2
  vault kv put secret/sensitive-transport-crypto/rsa-ciam bootstrap=true
'
```

如果 `secret/` 已存在，说明这个 Vault 不是全新实例；不要重复启用或覆盖，应先确认已有数据和密钥。

## 3. 生成应用令牌、初始 RSA 密钥和 Kong 只读令牌

创建应用要共享的随机 gateway token，并将它存为 Kubernetes Secret。Server 只从这个 Secret 读取 token；不要把真实 token 写入 YAML：

```bash
kubectl create namespace encryptpii --dry-run=client -o yaml | kubectl apply -f -
openssl rand -hex 32 > vault/.local/gateway-token
chmod 600 vault/.local/gateway-token
kubectl -n encryptpii create secret generic encryptpii-gateway \
  --from-file=token=vault/.local/gateway-token \
  --dry-run=client -o yaml | kubectl apply -f -
```

Vault 只读 token 将交给 Kong；创建仅能读取目标 KV v2 数据和元数据的策略：

```bash
{
  jq -er '.root_token' vault/.local/init.json
  printf '%s\n' \
    'path "secret/data/sensitive-transport-crypto/rsa-ciam" { capabilities = ["read"] }' \
    'path "secret/metadata/sensitive-transport-crypto/rsa-ciam" { capabilities = ["read"] }'
} | kubectl -n vault exec -i vault-0 -- sh -c '
  IFS= read -r VAULT_TOKEN
  export VAULT_TOKEN
  vault policy write encryptpii-kong -
'
```

使用 root token 创建初始 RSA 密钥版本。脚本默认通过 `kubectl exec` 调用 Vault Pod 内的 CLI，无需端口转发；RSA 密钥在本机生成。需要本机的 `kubectl`、`jq` 和 `openssl`：

```bash
VAULT_TOKEN="$(jq -er '.root_token' vault/.local/init.json)" \
  ./vault/scripts/rotate-vault-key.sh \
  secret/data/sensitive-transport-crypto/rsa-ciam
```

然后生成短期、无父 token 的 Kong 只读 token：

```bash
jq -er '.root_token' vault/.local/init.json |
  kubectl -n vault exec -i vault-0 -- sh -c '
    IFS= read -r VAULT_TOKEN
    export VAULT_TOKEN
    vault token create -policy=encryptpii-kong -orphan -ttl=720h -format=json
  ' > vault/.local/kong-token.json
chmod 600 vault/.local/kong-token.json
jq -jr '.auth.client_token' vault/.local/kong-token.json > vault/.local/kong-token
chmod 600 vault/.local/kong-token
```

另外创建一个仅用于手动轮换密钥、具有目标数据路径读写权限的 token：

```bash
{
  jq -er '.root_token' vault/.local/init.json
  printf '%s\n' \
    'path "secret/data/sensitive-transport-crypto/rsa-ciam" { capabilities = ["read", "update"] }'
} | kubectl -n vault exec -i vault-0 -- sh -c '
  IFS= read -r VAULT_TOKEN
  export VAULT_TOKEN
  vault policy write encryptpii-rotation -
'
jq -er '.root_token' vault/.local/init.json |
  kubectl -n vault exec -i vault-0 -- sh -c '
    IFS= read -r VAULT_TOKEN
    export VAULT_TOKEN
    vault token create -policy=encryptpii-rotation -orphan -ttl=720h -format=json
  ' > vault/.local/rotation-token.json
chmod 600 vault/.local/rotation-token.json
jq -jr '.auth.client_token' vault/.local/rotation-token.json > vault/.local/rotation-token
chmod 600 vault/.local/rotation-token
```

创建 Kong 命名空间和 Vault token Secret：

```bash
kubectl create namespace kong --dry-run=client -o yaml | kubectl apply -f -
kubectl -n kong create secret generic encryptpii-vault \
  --from-file=token=vault/.local/kong-token \
  --dry-run=client -o yaml | kubectl apply -f -
```

## 4. 配置 Kong

复制配置模板：

```bash
cp .env.example .env
```

编辑仓库根目录 `.env` 中以下设置。把 `ENCRYPTPII_VAULT_TOKEN` 设置为 `vault/.local/kong-token` 文件中的 token；gateway token 不需要写入此文件，部署脚本会从 Kubernetes Secret 读取。

```dotenv
ENCRYPTPII_VAULT_ADDR=http://vault.vault.svc.cluster.local:8200
ENCRYPTPII_VAULT_SECRET_PATH=secret/data/sensitive-transport-crypto/rsa-ciam
ENCRYPTPII_KEY_ALIAS=rsa-ciam
ENCRYPTPII_VAULT_TOKEN=<vault/.local/kong-token 中的实际内容>
ENCRYPTPII_KEY_VALIDITY_MILLIS=3600000
ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS=600000
ENCRYPTPII_MAX_BODY_BYTES=1048576
```

其余模板项在本部署模式下不会用于配置 Kubernetes 上游地址；Kong 的 upstream 和 Vault Service 地址由 Kubernetes 部署脚本设置。根目录 `.env` 含敏感 token，切勿提交到 Git。

## 5. 构建并部署 Server

构建 Spring Boot JAR 和容器镜像：

```bash
./gradlew :server:bootJar
docker build -t encryptpii-server:local server
```

Docker Desktop Kubernetes 使用独立 containerd 镜像库时，需要将本机 Docker 镜像导入 Kubernetes 节点。下面创建一个临时节点调试 Pod，一次导入 Server 和 Client 镜像；命令完成后会删除该 Pod：

```bash
./gradlew :client:bootJar
docker build -t encryptpii-client:local client

helper="$(kubectl debug node/desktop-control-plane --image=alpine:3.21 \
  --profile=sysadmin -- sleep 600 |
  sed -n 's/^Creating debugging pod \([^ ]*\).*/\1/p')"
test -n "$helper"
kubectl wait --for=condition=Ready "pod/$helper" --timeout=90s
docker image save encryptpii-server:local |
  kubectl exec -i "$helper" -- chroot /host ctr -n k8s.io images import -
docker image save encryptpii-client:local |
  kubectl exec -i "$helper" -- chroot /host ctr -n k8s.io images import -
kubectl delete pod "$helper"
```

应用 Server manifest 并等待就绪：

```bash
kubectl apply -f server/k8s/server.yaml
kubectl -n encryptpii rollout status deployment/encryptpii-server --timeout=180s
```

Server 只允许带正确 `X-Crypto-Gateway-Token` 的 Kong 内部请求。它不访问 Vault；Vault 密钥读取和加解密均由 Kong 插件处理。

## 6. 部署 Kong 和插件路由

脚本会构建自定义 Kong 镜像、导入 Docker Desktop Kubernetes 节点、生成 DB-less 配置，并部署四条路由。它也会把 `encryptpii` 命名空间中的 gateway Secret 复制到 `kong` 命名空间：

```bash
./sensitive-transport-crypto/scripts/deploy-to-k8s.sh
kubectl -n kong rollout status deployment/encryptpii-kong --timeout=180s
```

Kong 部署脚本默认使用集群内的 `vault.vault.svc.cluster.local:8200`，要求先通过 Vault 部署脚本创建好 `kong/encryptpii-vault` Secret；不会用 `.env` 中的令牌覆盖它。无需 `--vault-in-k8s`（旧参数仍兼容）。不要对 DB-less Kong 执行 `configure-routes.sh`；需要修改路由或配置时重新运行上面的部署脚本。

## 7. 部署 Client 并调用演示接口

Client manifest 已将 Kong 地址设为集群内 Service：`http://encryptpii-kong.kong.svc.cluster.local:8000`。Client 无需直接访问 Server 或 Vault：

另有无加解密的演示链路：`/plain/client/*` → Kong `/plain/server/*` → Server `/plain/server/*`。Kong 使用独立的 `encryptpii-server-plain` Service 和无插件路由，保留请求路径直接转发；不读取 Vault，不附加加密或 gateway token。原有 `/crypto/client/*` 加密链路保持不变。

Client 的目标 URL 统一配置在 `client/src/main/resources/application.yml`：`crypto.server` 为加密接口，`plain.server` 为非加密接口，各自配置 `base-url` 和 `endpoints`。明文默认复用加密链路的 Kong 地址；可用 `PLAIN_SERVER_BASE_URL` 单独覆盖。修改接口目标路径时需同步 Kong 路由。

```bash
kubectl apply -f client/k8s/client.yaml
kubectl -n encryptpii rollout status deployment/encryptpii-client --timeout=180s
```

Client Service 使用 `LoadBalancer`，对外端口 `18080` 转发到容器端口 `8080`。查看入口状态：

```bash
kubectl -n encryptpii get service encryptpii-client
```

Docker Desktop 的 LoadBalancer 就绪后，直接访问 `http://localhost:18080`，无需保持端口转发进程。若集群未提供 LoadBalancer，可用 `bash client/scripts/port-forward.sh` 临时调试（本机端口被占用时需先释放）。

检查健康状态，并发送双向加密演示请求：

```bash
curl --fail-with-body http://localhost:18080/actuator/health
curl --fail-with-body -X POST http://localhost:18080/crypto/client/bidirectional \
  -H 'Content-Type: application/json' \
  --data '{"name":"demo","phone":"1234567890","email":"demo@example.com","address":"demo address"}'
```

明文演示使用 URL `/plain/client/normal`，请求体为 `DemoPlainRequest`，例如 `{"data":"demo"}`。Client 仅保留这个明文接口，不执行加解密，直接返回 Server 的响应体和状态码；目标由 `plain.server.endpoints.normal` 配置，为 `/plain/server/normal`，Kong 不挂载插件且保留原路径转发至 Server `/plain/server/normal`。明文链路仅供本地演示，不应在生产环境公开敏感数据。

Client 会从 Kong 获取 Vault 中的活动公钥；请求经 RSA-OAEP/AES-GCM 加密后送到 Kong。Kong 从 Vault 读取对应私钥版本、解密请求、使用 gateway token 将明文转发给 Server，再用同一会话密钥加密响应。也可调用 `POST /crypto/client/request-only` 或 `POST /crypto/client/response-only`。

如需直接检查 Kong 公钥接口，可在额外终端转发 Kong：

```bash
kubectl -n kong port-forward service/encryptpii-kong 18000:8000
curl --fail-with-body http://localhost:18000/crypto/server/public-key
```

## 8. 日常维护和故障排查

- 查看组件状态：`kubectl get pods,svc -n vault`、`kubectl get pods,svc -n kong`、`kubectl get pods,svc -n encryptpii`。
- 查看日志：`kubectl -n kong logs deployment/encryptpii-kong`、`kubectl -n encryptpii logs deployment/encryptpii-server`、`kubectl -n encryptpii logs deployment/encryptpii-client`。
- Vault Pod 重启后可能需要重新解封：运行 `./vault/scripts/unseal.sh`。
- 公钥接口失败时，确认 Vault Pod 已解封、`kong/encryptpii-vault` token 有效、KV 路径与 `ENCRYPTPII_VAULT_SECRET_PATH` 一致，并检查 RSA 密钥是否过期。
- 手动轮换密钥直接执行 `./vault/scripts/rotate-vault-key.sh`，默认通过 `kubectl exec` 访问 Kubernetes Vault，读取 `vault/.local/rotation-token`，无需端口转发。可加 `--dry-run` 预演；显式 `VAULT_TOKEN` 优先。访问外部 Vault 时使用 `--http` 并指定 `VAULT_ADDR` 和专用轮换令牌。
- 本地 Vault、Kong 和应用之间使用 HTTP；演示 token 有有效期，且 Vault 为单节点，不适用于生产环境。生产部署需另行启用 TLS、HA/自动解封、备份和 token 续期策略。
