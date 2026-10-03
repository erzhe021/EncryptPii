#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
LOCAL_DIR="$REPO_DIR/vault/.local"
if [[ "${1:-}" == --help ]]; then
  printf '用法: vault/scripts/deploy-to-k8s.sh\n部署 Vault；首次初始化密钥和令牌，重复运行保留数据。\n'
  exit 0
fi
if [[ "$#" -ne 0 ]]; then
  printf '此脚本不接受参数，使用 --help 查看用法。\n' >&2
  exit 2
fi
for command in kubectl jq openssl mktemp grep cmp; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf '缺少命令：%s\n' "$command" >&2
    exit 1
  fi
done
if [[ "$(kubectl config current-context)" != docker-desktop ]]; then
  printf '此脚本要求 docker-desktop context。\n' >&2
  exit 1
fi
source "$REPO_DIR/sensitive-transport-crypto/scripts/load-env.sh"
load_plugin_env "$REPO_DIR/.env"
secret_path="${ENCRYPTPII_VAULT_SECRET_PATH:-}"
if [[ ! "$secret_path" =~ ^secret/data/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$ ]]; then
  printf '请在根目录 .env 设置有效的 secret/data/... 密钥路径。\n' >&2
  exit 1
fi
metadata_path="secret/metadata/${secret_path#secret/data/}"
source "$SCRIPT_DIR/common.sh"
mkdir -p "$LOCAL_DIR"
chmod 700 "$LOCAL_DIR"
work_dir="$(mktemp -d)"
trap 'rm -f "$work_dir/status.json" "$work_dir/status.err" "$work_dir/metadata.json" "$work_dir/metadata.err" "$work_dir/private.pem" "$work_dir/private.der" "$work_dir/public.der" "$work_dir/derived-public.der" "$work_dir/private.b64" "$work_dir/public.b64" "$work_dir/payload.json"; rmdir "$work_dir"' EXIT

kubectl apply -f "$REPO_DIR/vault/k8s/vault.yaml"
# 未初始化或封存的 Vault 不会 Ready；先等容器启动，再读取封存状态。
kubectl -n vault wait --for=jsonpath='{.status.phase}'=Running pod/vault-0 --timeout=180s
for ((attempt=1; attempt<=60; attempt++)); do
  if kubectl -n vault exec vault-0 -- sh -c \
    'vault status -format=json; code=$?; test "$code" -eq 0 -o "$code" -eq 2' \
    > "$work_dir/status.json" 2> "$work_dir/status.err"; then
    break
  fi
  if [[ "$attempt" -eq 60 ]]; then
    printf '等待 Vault API 启动超时：\n' >&2
    cat "$work_dir/status.err" >&2
    exit 1
  fi
  sleep 1
done
if [[ "$(jq -er '.initialized | tostring' "$work_dir/status.json")" == false ]]; then
  if [[ -e "$LOCAL_DIR/init.json" ]]; then
    printf 'Vault 尚未初始化，但本地已有 init.json；请先安全归档旧凭据，拒绝覆盖。\n' >&2
    exit 1
  fi
  kubectl -n vault exec vault-0 -- vault operator init \
    -key-shares=1 -key-threshold=1 -format=json > "$LOCAL_DIR/init.json"
fi
if [[ ! -f "$LOCAL_DIR/init.json" ]]; then
  printf '缺少 vault/.local/init.json，无法自动管理已有 Vault，请恢复正确凭据。\n' >&2
  exit 1
fi
if [[ "$(jq -er '.sealed | tostring' "$work_dir/status.json")" == true ]]; then
  "$SCRIPT_DIR/unseal.sh"
fi
kubectl -n vault rollout status statefulset/vault --timeout=180s

admin /dev/null token lookup -format=json >/dev/null
mounts="$(admin /dev/null secrets list -format=json)"
if ! printf '%s' "$mounts" | jq -e 'has("secret/")' >/dev/null; then
  admin /dev/null secrets enable -path=secret kv-v2 >/dev/null
elif ! printf '%s' "$mounts" | jq -e '."secret/".type == "kv" and ."secret/".options.version == "2"' >/dev/null; then
  printf '已有 secret/ 挂载不是 KV v2，拒绝修改。\n' >&2
  exit 1
fi

if admin /dev/null kv metadata get -format=json "secret/${secret_path#secret/data/}" \
  > "$work_dir/metadata.json" 2> "$work_dir/metadata.err"; then
  printf '已有密钥版本 %s，保留不轮换。\n' "$(jq -er '.data.current_version' "$work_dir/metadata.json")"
  if ! jq -e '.data.current_version as $v | .data.versions[($v|tostring)] |
    .destroyed == false and .deletion_time == ""' "$work_dir/metadata.json" >/dev/null; then
    printf '当前 Vault 密钥版本已删除或销毁，拒绝报告部署成功。\n' >&2
    exit 1
  fi
  admin /dev/null read -format=json "$secret_path" > "$work_dir/payload.json"
  if ! jq -e '.data.data | (.publicKey | type == "string" and length > 0)
    and (.privateKey | type == "string" and length > 0)' "$work_dir/payload.json" >/dev/null; then
    printf '已有 Vault 密钥缺少有效的 publicKey/privateKey，请修复或轮换。\n' >&2
    exit 1
  fi
  jq -jr '.data.data.privateKey' "$work_dir/payload.json" > "$work_dir/private.b64"
  jq -jr '.data.data.publicKey' "$work_dir/payload.json" > "$work_dir/public.b64"
  openssl base64 -d -A -in "$work_dir/private.b64" -out "$work_dir/private.der"
  openssl base64 -d -A -in "$work_dir/public.b64" -out "$work_dir/public.der"
  openssl rsa -inform DER -in "$work_dir/private.der" -check -noout >/dev/null
  openssl pkey -inform DER -in "$work_dir/private.der" -pubout -outform DER \
    -out "$work_dir/derived-public.der"
  if ! cmp -s "$work_dir/public.der" "$work_dir/derived-public.der"; then
    printf 'Vault 公钥和私钥不匹配，请修复或轮换。\n' >&2
    exit 1
  fi
else
  if ! grep -q 'No value found' "$work_dir/metadata.err"; then
    cat "$work_dir/metadata.err" >&2
    exit 1
  fi
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$work_dir/private.pem"
  openssl pkcs8 -topk8 -nocrypt -in "$work_dir/private.pem" -outform DER -out "$work_dir/private.der"
  openssl pkey -in "$work_dir/private.pem" -pubout -outform DER -out "$work_dir/public.der"
  openssl base64 -A -in "$work_dir/private.der" -out "$work_dir/private.b64"
  openssl base64 -A -in "$work_dir/public.der" -out "$work_dir/public.b64"
  jq -n --rawfile private "$work_dir/private.b64" --rawfile public "$work_dir/public.b64" \
    '{options:{cas:0},data:{privateKey:$private,publicKey:$public}}' > "$work_dir/payload.json"
  admin "$work_dir/payload.json" write "$secret_path" - >/dev/null
fi

configure_application_tokens
printf 'Vault 已部署；凭据保存在 vault/.local/，请安全备份。无需端口转发即可完成初始化。\n'
