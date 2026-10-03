#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOCAL_DIR="$REPO_DIR/vault/.local"

if [[ "$#" -ne 0 ]]; then
  printf '用法: scripts/rebuild-local-k8s.sh\n' >&2
  exit 2
fi
for command in docker kubectl jq openssl mktemp sed grep cmp; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf '缺少命令: %s\n' "$command" >&2
    exit 1
  fi
done
if [[ "$(kubectl config current-context)" != docker-desktop ]]; then
  printf '此脚本要求当前 Kubernetes context 为 docker-desktop。\n' >&2
  exit 1
fi
source "$REPO_DIR/sensitive-transport-crypto/scripts/load-env.sh"
load_plugin_env "$REPO_DIR/.env"
validate_crypto_config

# 清理前完成配置校验和镜像构建，部署时复用这些镜像。
bash "$REPO_DIR/server/scripts/build-image.sh"
bash "$REPO_DIR/client/scripts/build-image.sh"
bash "$REPO_DIR/sensitive-transport-crypto/scripts/build-plugin.sh"
bash "$SCRIPT_DIR/cleanup-local-k8s.sh"

mkdir -p "$LOCAL_DIR"
chmod 700 "$LOCAL_DIR"
credential_archive=""
for file in init.json gateway-token kong-token kong-token.json rotation-token rotation-token.json; do
  if [[ -e "$LOCAL_DIR/$file" ]]; then
    if [[ -z "$credential_archive" ]]; then
      credential_archive="$(mktemp -d "$LOCAL_DIR/previous-XXXXXXXX")"
    fi
    mv "$LOCAL_DIR/$file" "$credential_archive/$file"
  fi
done
if [[ -n "$credential_archive" ]]; then
  printf '旧的本地凭据已归档到 %s\n' "$credential_archive"
fi

bash "$REPO_DIR/vault/scripts/deploy-to-k8s.sh"
gateway_token="$(openssl rand -hex 32)"
printf '%s' "$gateway_token" > "$LOCAL_DIR/gateway-token"
ENCRYPTPII_GATEWAY_TOKEN="$gateway_token" KONG_CRYPTO_GATEWAY_TOKEN="$gateway_token" \
  bash "$REPO_DIR/server/scripts/deploy-to-k8s.sh" --skip-build
bash "$REPO_DIR/sensitive-transport-crypto/scripts/deploy-to-k8s.sh" --skip-build
bash "$REPO_DIR/client/scripts/deploy-to-k8s.sh" --skip-build

printf '\n重建完成。访问 Client：\n'
printf 'Docker Desktop LoadBalancer 就绪后可直接访问：http://localhost:18080\n'
printf 'Vault 初始化凭据和新 token 保存在 %s\n' "$LOCAL_DIR"
