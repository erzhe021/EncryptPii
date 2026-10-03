#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
usage() {
  printf '%s\n' \
    '用法: scripts/cleanup-local-k8s.sh [--yes]' \
    '删除 docker-desktop 集群中的 vault、kong、encryptpii 命名空间及其全部资源，' \
    '并删除这些命名空间所拥有的 PersistentVolume。Vault 数据将无法恢复。' \
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

namespaces=(vault kong encryptpii)
if [[ "$assume_yes" != true ]]; then
  printf '即将删除命名空间及其中所有资源：%s\n' "${namespaces[*]}"
  printf 'Vault PVC 和其中的密钥/数据也会被删除，且无法恢复。\n'
  printf '如确认，请输入 DELETE：'
  IFS= read -r confirmation
  if [[ "$confirmation" != DELETE ]]; then
    printf '已取消。\n'
    exit 1
  fi
fi

volume_names="$(
  kubectl get persistentvolumes -o json |
    jq -r '
      .items[]
      | select(.spec.claimRef.namespace == "vault" and .spec.claimRef.name != "data-vault-0")
      | .metadata.name
    '
)"

bash "$REPO_DIR/client/scripts/delete-from-k8s.sh" --yes
bash "$REPO_DIR/sensitive-transport-crypto/scripts/delete-from-k8s.sh" --yes
bash "$REPO_DIR/server/scripts/delete-from-k8s.sh" --yes
bash "$REPO_DIR/vault/scripts/delete-from-k8s.sh" --purge-data --yes

for namespace in "${namespaces[@]}"; do
  kubectl delete namespace "$namespace" --ignore-not-found --wait=true --timeout=300s
done

while IFS= read -r volume; do
  [[ -n "$volume" ]] || continue
  kubectl delete persistentvolume "$volume" --ignore-not-found --wait=true --timeout=300s
done <<< "$volume_names"

printf '已删除指定项目命名空间及其持久卷资源。\n'
