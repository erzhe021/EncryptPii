#!/usr/bin/env bash
set -euo pipefail

component="${1:-}"
case "$component" in
  client|server|kong|vault) shift ;;
  *)
    printf '用法: scripts/lib/delete-k8s-component.sh {client|server|kong|vault} [--yes] [--purge-data]\n' >&2
    exit 2
    ;;
esac

usage() {
  component_dir="$component"
  if [[ "$component" == kong ]]; then
    component_dir=sensitive-transport-crypto
  fi
  printf '用法: %s/scripts/delete-from-k8s.sh [--yes]' "$component_dir"
  if [[ "$component" == vault ]]; then
    printf ' [--purge-data]'
  fi
  printf '\n仅删除指定组件的资源，保留命名空间和本地文件。\n'
  printf 'Client/Server 保留共享 gateway Secret；Kong 删除自身配置和 Secret 副本。\n'
  if [[ "$component" == vault ]]; then
    printf 'Vault 默认保留 PVC；--purge-data 删除 data-vault-0 及其关联 PV，数据无法恢复。\n'
  fi
  printf '%s\n' '--yes 跳过交互确认。'
}
assume_yes=false
purge_data=false
for argument in "$@"; do
  case "$argument" in
    --help|-h) usage; exit 0 ;;
    --yes) assume_yes=true ;;
    --purge-data)
      if [[ "$component" != vault ]]; then
        printf '%s\n' '--purge-data 仅适用于 Vault。' >&2
        exit 2
      fi
      purge_data=true
      ;;
    *) usage >&2; exit 2 ;;
  esac
done
if ! command -v kubectl >/dev/null 2>&1; then
  printf '缺少命令：kubectl\n' >&2
  exit 1
fi
if [[ "$(kubectl config current-context)" != docker-desktop ]]; then
  printf '拒绝删除：当前 context 不是 docker-desktop。\n' >&2
  exit 1
fi
if [[ "$purge_data" == true ]] && ! command -v jq >/dev/null 2>&1; then
  printf '彻底删除 Vault 持久数据需要 jq。\n' >&2
  exit 1
fi
if [[ "$assume_yes" != true ]]; then
  printf '即将删除组件 %s 的 Kubernetes 资源。\n' "$component"
  if [[ "$purge_data" == true ]]; then
    printf '警告：Vault PVC 和关联 PV 也将删除，密钥和数据无法恢复。\n'
  fi
  printf '请输入 DELETE 确认：'
  IFS= read -r confirmation
  if [[ "$confirmation" != DELETE ]]; then
    printf '已取消。\n'
    exit 1
  fi
fi

delete_resource() {
  kubectl -n "$1" delete "$2" "${@:3}" --ignore-not-found --wait=true --timeout=180s
}
case "$component" in
  client|server)
    delete_resource encryptpii deployment "encryptpii-$component"
    delete_resource encryptpii service "encryptpii-$component"
    ;;
  kong)
    delete_resource kong deployment encryptpii-kong
    delete_resource kong service encryptpii-kong
    delete_resource kong configmap encryptpii-kong-config
    delete_resource kong secret encryptpii-vault encryptpii-gateway
    ;;
  vault)
    volume_names=""
    if [[ "$purge_data" == true ]]; then
      volume_names="$(kubectl get persistentvolumes -o json |
        jq -r '.items[] | select(.spec.claimRef.namespace == "vault" and .spec.claimRef.name == "data-vault-0") | .metadata.name')"
    fi
    delete_resource vault statefulset vault
    delete_resource vault service vault vault-internal
    delete_resource vault configmap vault-config
    if [[ "$purge_data" == true ]]; then
      delete_resource vault persistentvolumeclaim data-vault-0
      while IFS= read -r volume; do
        [[ -n "$volume" ]] || continue
        kubectl delete persistentvolume "$volume" --ignore-not-found --wait=true --timeout=180s
      done <<< "$volume_names"
      delete_resource kong secret encryptpii-vault
      printf 'Vault 数据已删除。再次初始化前，请安全归档 vault/.local/ 中旧的初始化凭据和 Vault token。\n'
    else
      printf 'Vault PVC、集群内令牌 Secret 和本地凭据已保留，可通过独立部署脚本恢复。\n'
    fi
    ;;
esac
printf '组件 %s 的指定资源已删除，命名空间保留。\n' "$component"
