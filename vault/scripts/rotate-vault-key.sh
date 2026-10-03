#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  printf '%s\n' \
    '用法: rotate-vault-key.sh [--vault-in-k8s|--http] [--dry-run] [KV_V2_DATA_PATH]' \
    '默认使用 kubectl exec 访问 docker-desktop 中的 vault/vault-0，无需端口转发。' \
    '默认令牌来自 vault/.local/rotation-token；VAULT_TOKEN 可显式覆盖。' \
    '密钥路径默认读取根目录 .env 中的 ENCRYPTPII_VAULT_SECRET_PATH。' \
    '--http 使用本机 curl；VAULT_ADDR/VAULT_TOKEN 覆盖根目录 .env 配置。' \
    '目标密钥必须已存在；保留其他字段，使用 CAS 写入新的 RSA-2048 版本。' \
    '--dry-run 读取密钥并准备新密钥，但不写入 Vault。'
}

dry_run=false
transport=k8s
transport_selected=false
secret_path=""
for argument in "$@"; do
  case "$argument" in
    --help|-h) usage; exit 0 ;;
    --dry-run) dry_run=true ;;
    --vault-in-k8s|--http)
      if [[ "$transport_selected" == true ]]; then
        printf '访问模式只能指定一次。\n' >&2
        exit 2
      fi
      transport_selected=true
      if [[ "$argument" == --http ]]; then
        transport=http
      fi
      ;;
    -*)
      printf 'Unknown option: %s\n' "$argument" >&2
      exit 1
      ;;
    *)
      if [[ -n "$secret_path" ]]; then
        usage >&2
        exit 1
      fi
      secret_path="$argument"
      ;;
  esac
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
KONG_DIR="$REPO_DIR/kong"
source "$KONG_DIR/scripts/load-env.sh"
source "$SCRIPT_DIR/common.sh"
if [[ -f "$REPO_DIR/.env" ]]; then
  load_plugin_env "$REPO_DIR/.env"
fi
vault_addr="${VAULT_ADDR:-${ENCRYPTPII_VAULT_ADDR:-}}"
if [[ -z "${VAULT_ADDR:-}" ]]; then
  case "$vault_addr" in
    http://host.docker.internal|http://host.docker.internal:*|http://host.docker.internal/*)
      vault_addr="http://localhost${vault_addr#http://host.docker.internal}"
      ;;
    https://host.docker.internal|https://host.docker.internal:*|https://host.docker.internal/*)
      vault_addr="https://localhost${vault_addr#https://host.docker.internal}"
      ;;
  esac
fi
if [[ "$transport" == k8s ]]; then
  if ! command -v kubectl >/dev/null 2>&1; then
    printf '缺少命令：kubectl\n' >&2
    exit 1
  fi
  if [[ "$(kubectl config current-context)" != docker-desktop ]]; then
    printf 'Kubernetes 轮换要求 docker-desktop context。\n' >&2
    exit 1
  fi
  if [[ -n "${VAULT_TOKEN:-}" ]]; then
    vault_token="$VAULT_TOKEN"
  elif [[ -s "$SCRIPT_DIR/../.local/rotation-token" ]]; then
    vault_token="$(cat "$SCRIPT_DIR/../.local/rotation-token")"
  else
    printf '缺少 vault/.local/rotation-token；请部署 Vault 或显式设置 VAULT_TOKEN。\n' >&2
    exit 1
  fi
else
  vault_token="${VAULT_TOKEN:-${ENCRYPTPII_VAULT_TOKEN:-}}"
fi
secret_path="${secret_path:-${ENCRYPTPII_VAULT_SECRET_PATH:-}}"

if [[ -z "$vault_token" || ( "$transport" == http && ! "$vault_addr" =~ ^https?://[^[:space:]]+$ ) ]]; then
  printf 'Set a valid VAULT_ADDR and a nonempty VAULT_TOKEN (or the matching ENCRYPTPII variables in the repository-root .env).\n' >&2
  exit 1
fi
if [[ ! "$secret_path" =~ ^[A-Za-z0-9_-]+/data/[A-Za-z0-9/_-]+$ ]]; then
  printf 'Specify a KV v2 data path, e.g. secret/data/sensitive-transport-crypto/rsa-ciam.\n' >&2
  exit 1
fi
if [[ "$vault_token" == *$'\r'* || "$vault_token" == *$'\n'* ]]; then
  printf 'Vault token must not contain line breaks.\n' >&2
  exit 1
fi
commands=(jq openssl mktemp)
if [[ "$transport" == http ]]; then
  commands+=(curl)
fi
for command in "${commands[@]}"; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'Required command not found: %s\n' "$command" >&2
    exit 1
  fi
done

work_dir="$(mktemp -d)"
trap 'rm -f "$work_dir/token-header" "$work_dir/current.json" "$work_dir/private.pem" "$work_dir/private.der" "$work_dir/public.der" "$work_dir/private.b64" "$work_dir/public.b64" "$work_dir/payload.json" "$work_dir/result.json"; rmdir "$work_dir"' EXIT
if [[ "$transport" == k8s ]]; then
  vault_exec "$vault_token" /dev/null read -format=json "$secret_path" > "$work_dir/current.json"
else
  printf 'X-Vault-Token: %s\n' "$vault_token" > "$work_dir/token-header"
  curl --silent --show-error --fail --connect-timeout 5 --max-time 30 \
    -H "@$work_dir/token-header" \
    "${vault_addr%/}/v1/$secret_path" > "$work_dir/current.json"
fi
version="$(jq -er '.data.metadata.version | select(type == "number" and . > 0 and . == floor)' "$work_dir/current.json")"
jq -e '.data.data | type == "object"' "$work_dir/current.json" >/dev/null

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out "$work_dir/private.pem" 2> /dev/null
openssl pkcs8 -topk8 -nocrypt -in "$work_dir/private.pem" \
  -outform DER -out "$work_dir/private.der"
openssl pkey -in "$work_dir/private.pem" -pubout \
  -outform DER -out "$work_dir/public.der"
openssl base64 -A -in "$work_dir/private.der" -out "$work_dir/private.b64"
openssl base64 -A -in "$work_dir/public.der" -out "$work_dir/public.b64"
jq --rawfile private_key "$work_dir/private.b64" \
  --rawfile public_key "$work_dir/public.b64" --argjson version "$version" \
  '{options:{cas:$version},data:(.data.data + {publicKey:$public_key,privateKey:$private_key})}' \
  "$work_dir/current.json" > "$work_dir/payload.json"

if [[ "$dry_run" == true ]]; then
  printf 'Dry run: prepared RSA keys for %s with CAS version %s; no version was written.\n' "$secret_path" "$version"
  exit 0
fi

if [[ "$transport" == k8s ]]; then
  vault_exec "$vault_token" "$work_dir/payload.json" write -format=json "$secret_path" - \
    > "$work_dir/result.json"
else
  curl --silent --show-error --fail-with-body --connect-timeout 5 --max-time 30 \
    -X POST -H "@$work_dir/token-header" -H 'Content-Type: application/json' \
    --data-binary "@$work_dir/payload.json" \
    "${vault_addr%/}/v1/$secret_path" > "$work_dir/result.json"
fi
new_version="$(jq -er '.data.version | select(type == "number" and . > 0)' "$work_dir/result.json")"
printf 'Created Vault secret %s version %s (previous version %s).\n' "$secret_path" "$new_version" "$version"
