#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  printf '%s\n' \
    'Usage: rotate-vault-key.sh [--dry-run] [KV_V2_DATA_PATH]' \
    'Generate an RSA-2048 key pair and create a new Vault KV v2 version.' \
    'Path defaults to ENCRYPTPII_VAULT_SECRET_PATH in the plugin .env.' \
    'VAULT_ADDR and VAULT_TOKEN override the plugin Vault address and token.' \
    'Example: VAULT_ADDR=http://localhost:8200 ./scripts/rotate-vault-key.sh secret/data/sensitive-transport-crypto/rsa-ciam' \
    'The target secret must already exist. Other secret fields are preserved.' \
    '--dry-run reads the secret and prepares keys without writing to Vault.'
}

dry_run=false
secret_path=""
for argument in "$@"; do
  case "$argument" in
    --help|-h) usage; exit 0 ;;
    --dry-run) dry_run=true ;;
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
source "$SCRIPT_DIR/load-env.sh"
if [[ -f "$SCRIPT_DIR/../.env" ]]; then
  load_plugin_env "$SCRIPT_DIR/../.env"
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
vault_token="${VAULT_TOKEN:-${ENCRYPTPII_VAULT_TOKEN:-}}"
secret_path="${secret_path:-${ENCRYPTPII_VAULT_SECRET_PATH:-}}"

if [[ ! "$vault_addr" =~ ^https?://[^[:space:]]+$ || -z "$vault_token" ]]; then
  printf 'Set a valid VAULT_ADDR and a nonempty VAULT_TOKEN (or the matching ENCRYPTPII variables).\n' >&2
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
for command in curl jq openssl mktemp; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'Required command not found: %s\n' "$command" >&2
    exit 1
  fi
done

work_dir="$(mktemp -d)"
trap 'rm -f "$work_dir/token-header" "$work_dir/current.json" "$work_dir/private.pem" "$work_dir/private.der" "$work_dir/public.der" "$work_dir/private.b64" "$work_dir/public.b64" "$work_dir/payload.json" "$work_dir/result.json"; rmdir "$work_dir"' EXIT
printf 'X-Vault-Token: %s\n' "$vault_token" > "$work_dir/token-header"

curl --silent --show-error --fail --connect-timeout 5 --max-time 30 \
  -H "@$work_dir/token-header" \
  "${vault_addr%/}/v1/$secret_path" > "$work_dir/current.json"
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

curl --silent --show-error --fail-with-body --connect-timeout 5 --max-time 30 \
  -X POST -H "@$work_dir/token-header" -H 'Content-Type: application/json' \
  --data-binary "@$work_dir/payload.json" \
  "${vault_addr%/}/v1/$secret_path" > "$work_dir/result.json"
new_version="$(jq -er '.data.version | select(type == "number" and . > 0)' "$work_dir/result.json")"
printf 'Created Vault secret %s version %s (previous version %s).\n' "$secret_path" "$new_version" "$version"
