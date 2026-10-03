#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
if [[ "${1:-}" == --help ]]; then
  printf '用法: server/scripts/deploy-to-k8s.sh [--skip-build]\n构建并部署 Server，保留已有 gateway Secret。\n'
  exit 0
fi
skip_build=false
if [[ "$#" -eq 1 && "$1" == --skip-build ]]; then
  skip_build=true
elif [[ "$#" -ne 0 ]]; then
  printf '此脚本不接受参数，使用 --help 查看用法。\n' >&2
  exit 2
fi
if [[ "$(kubectl config current-context)" != docker-desktop ]]; then
  printf '此脚本要求 docker-desktop context。\n' >&2
  exit 1
fi
source "$REPO_DIR/sensitive-transport-crypto/scripts/load-env.sh"
load_plugin_env "$REPO_DIR/.env"
kubectl create namespace encryptpii --dry-run=client -o yaml | kubectl apply -f -
gateway_secret="$(kubectl -n encryptpii get secret encryptpii-gateway --ignore-not-found -o name)"
if [[ -z "$gateway_secret" ]]; then
  token="${KONG_CRYPTO_GATEWAY_TOKEN:-${ENCRYPTPII_GATEWAY_TOKEN:-}}"
  if [[ "${#token}" -lt 32 || "$token" == replace-with-* || "$token" == *$'\n'* || "$token" == *$'\r'* ]]; then
    printf '首次部署需要根目录 .env 中有效且与 Kong 一致的 gateway token（至少 32 字符）。\n' >&2
    exit 1
  fi
  if [[ -n "${ENCRYPTPII_GATEWAY_TOKEN:-}" && "$token" != "$ENCRYPTPII_GATEWAY_TOKEN" ]]; then
    printf 'KONG_CRYPTO_GATEWAY_TOKEN 与 ENCRYPTPII_GATEWAY_TOKEN 不一致。\n' >&2
    exit 1
  fi
  work_dir="$(mktemp -d)"
  trap 'rm -f "$work_dir/token"; rmdir "$work_dir"' EXIT
  printf '%s' "$token" > "$work_dir/token"
  kubectl -n encryptpii create secret generic encryptpii-gateway --from-file=token="$work_dir/token"
fi
if [[ "$skip_build" != true ]]; then
  bash "$SCRIPT_DIR/build-image.sh"
fi
"$REPO_DIR/scripts/import-local-k8s-images.sh" encryptpii-server:local
kubectl apply -f "$REPO_DIR/server/k8s/server.yaml"
kubectl -n encryptpii rollout restart deployment/encryptpii-server
kubectl -n encryptpii rollout status deployment/encryptpii-server --timeout=180s
printf 'Server 已部署，集群内地址：http://encryptpii-server.encryptpii.svc.cluster.local:9090\n'
