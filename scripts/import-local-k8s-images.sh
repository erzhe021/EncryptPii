#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == --help || "$#" -eq 0 ]]; then
  printf '用法: scripts/import-local-k8s-images.sh IMAGE [IMAGE ...]\n'
  exit 0
fi
if [[ "$(kubectl config current-context)" != docker-desktop ]]; then
  printf '镜像导入仅支持 docker-desktop context。\n' >&2
  exit 1
fi
for image in "$@"; do
  docker image inspect "$image" >/dev/null
done

helper=""
cleanup() {
  if [[ -n "$helper" ]]; then
    kubectl -n default delete pod "$helper" --ignore-not-found --wait=true --timeout=60s
  fi
}
trap cleanup EXIT
helper="$(kubectl -n default debug node/desktop-control-plane --image=alpine:3.21 \
  --profile=sysadmin -- sleep 600 |
  sed -n 's/^Creating debugging pod \([^ ]*\).*/\1/p')"
if [[ -z "$helper" ]]; then
  printf '无法创建镜像导入 Pod。\n' >&2
  exit 1
fi
kubectl -n default wait --for=condition=Ready "pod/$helper" --timeout=90s
docker image save "$@" |
  kubectl -n default exec -i "$helper" -- chroot /host ctr -n k8s.io images import -
