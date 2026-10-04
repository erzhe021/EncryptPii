#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
if [[ "${1:-}" == --help ]]; then
  printf '用法: server/scripts/deploy-to-k8s.sh [--skip-build]\n构建并部署 Server，使用根目录 .env 中的 KONG_TO_ENCRYPTPII_AUTH_TOKEN。\n'
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
source "$REPO_DIR/kong/scripts/load-env.sh"
load_plugin_env "$REPO_DIR/.env"
validate_gateway_token
token="${KONG_TO_ENCRYPTPII_AUTH_TOKEN:-}"
kubectl create namespace encryptpii --dry-run=client -o yaml | kubectl apply -f -
work_dir="$(mktemp -d)"
trap 'rm -f "$work_dir/token"; rmdir "$work_dir"' EXIT
printf '%s' "$token" > "$work_dir/token"
kubectl -n encryptpii create secret generic encryptpii-gateway \
  --from-file=token="$work_dir/token" --dry-run=client -o yaml | kubectl apply -f -
if [[ "$skip_build" != true ]]; then
  bash "$SCRIPT_DIR/build-image.sh"
fi
"$REPO_DIR/scripts/import-local-k8s-images.sh" encryptpii-server:local
kubectl apply -f "$REPO_DIR/server/k8s/server.yaml"
kubectl -n encryptpii rollout restart deployment/encryptpii-server
kubectl -n encryptpii rollout status deployment/encryptpii-server --timeout=180s
printf 'Server 已部署，集群内地址：http://encryptpii-server.encryptpii.svc.cluster.local:9090\n'
