#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
usage() {
  printf '%s\n' \
    '用法: scripts/cleanup-local-k8s.sh [--yes]' \
    '仅删除 docker-desktop 集群中本项目的具名资源，保留命名空间和其他资源。' \
    '删除 Vault PVC data-vault-0 及其关联 PV。Vault 数据将无法恢复。' \
    '--yes 跳过交互确认。'
}

assume_yes=false
while (($#)); do
  case "$1" in
    --yes) assume_yes=true ;;
    --help|-h) usage; exit 0 ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  shift
done

for command in kubectl jq; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf '缺少命令: %s\n' "$command" >&2
    exit 1
  fi
done

context="$(kubectl config current-context)"
if [[ "$context" != docker-desktop ]]; then
  printf '拒绝清理：当前 Kubernetes context 是 %s，不是 docker-desktop。\n' "$context" >&2
  exit 1
fi

if [[ "$assume_yes" != true ]]; then
  printf '即将删除本项目的 Client、Server、Kong、Vault 资源和共享 gateway Secret；保留命名空间及其他资源。\n'
  printf 'Vault PVC 和其中的密钥/数据也会被删除，且无法恢复。\n'
  printf '如确认，请输入 DELETE：'
  IFS= read -r confirmation
  if [[ "$confirmation" != DELETE ]]; then
    printf '已取消。\n'
    exit 1
  fi
fi

bash "$REPO_DIR/client/scripts/delete-from-k8s.sh" --yes
bash "$REPO_DIR/kong/scripts/delete-from-k8s.sh" --yes
bash "$REPO_DIR/server/scripts/delete-from-k8s.sh" --yes
bash "$REPO_DIR/vault/scripts/delete-from-k8s.sh" --purge-data --yes

kubectl -n encryptpii delete secret encryptpii-gateway \
  --ignore-not-found --wait=true --timeout=180s

printf '已删除本项目的具名资源及 Vault 持久卷；命名空间、其他资源和本地文件已保留。\n'
