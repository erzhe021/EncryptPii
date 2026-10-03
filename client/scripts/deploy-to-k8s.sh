#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
if [[ "${1:-}" == --help ]]; then
  printf '用法: client/scripts/deploy-to-k8s.sh [--skip-build]\n构建并部署 Client，使用集群内 Kong 地址。\n'
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
if [[ "$skip_build" != true ]]; then
  bash "$SCRIPT_DIR/build-image.sh"
fi
"$REPO_DIR/scripts/import-local-k8s-images.sh" encryptpii-client:local
kubectl create namespace encryptpii --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "$REPO_DIR/client/k8s/client.yaml"
kubectl -n encryptpii rollout restart deployment/encryptpii-client
kubectl -n encryptpii rollout status deployment/encryptpii-client --timeout=180s
printf 'Client 已部署。Docker Desktop LoadBalancer 就绪后可直接访问：http://localhost:18080\n'
