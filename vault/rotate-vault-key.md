# Vault 密钥轮换

默认通过 `kubectl exec` 调用 Kubernetes 中 `vault/vault-0` 的 Vault CLI，无需端口转发。RSA 密钥在本机生成，令牌和写入数据通过标准输入传入 Pod。

在仓库根目录运行：

```bash
./vault/scripts/rotate-vault-key.sh --dry-run
./vault/scripts/rotate-vault-key.sh
```

脚本从自身路径定位仓库，所以也可以在其他目录通过绝对路径执行。默认要求 `docker-desktop` context，并从 `vault/.local/rotation-token` 读取专用令牌，不使用 `.env` 中的 Kong 只读令牌。显式设置 `VAULT_TOKEN` 可以覆盖令牌；`--vault-in-k8s` 可显式指定默认模式。

目标路径默认使用根目录 `.env` 的 `ENCRYPTPII_VAULT_SECRET_PATH`，也可以通过参数指定。目标 secret 必须已存在。`--dry-run` 不写入 Vault；实际写入使用 CAS 防止并发覆盖，并保留其他字段和历史版本。

访问外部 Vault 时，显式使用 HTTP 模式：

```bash
VAULT_ADDR=http://localhost:8200 VAULT_TOKEN='<专用轮换令牌>' \
  ./vault/scripts/rotate-vault-key.sh --http
```

令牌需要目标 KV v2 数据路径的 `read` 和 `update` 权限。轮换后 Kong 公钥接口会读取新版本，但 Client 可能仍使用未过期的缓存公钥。
