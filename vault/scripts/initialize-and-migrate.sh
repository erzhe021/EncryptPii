#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
LOCAL_DIR="$SCRIPT_DIR/../.local"
source "$REPO_DIR/kong/scripts/load-env.sh"
load_plugin_env "$REPO_DIR/.env"
if [[ "$(kubectl config current-context)" != docker-desktop ]]; then
  printf 'This script requires the docker-desktop context.\n' >&2
  exit 1
fi
secret_path="${ENCRYPTPII_VAULT_SECRET_PATH:?}"
if [[ ! "$secret_path" =~ ^secret/data/[A-Za-z0-9/_-]+$ ]]; then
  printf 'Migration requires a secret/data/... KV v2 path.\n' >&2
  exit 1
fi
source_addr="${SOURCE_VAULT_ADDR:-http://localhost:8200}"
source_token="${SOURCE_VAULT_TOKEN:?Set SOURCE_VAULT_TOKEN for the source Vault migration}"
metadata_path="secret/metadata/${secret_path#secret/data/}"
source "$SCRIPT_DIR/common.sh"
mkdir -p "$LOCAL_DIR"
chmod 700 "$LOCAL_DIR"
work_dir="$(mktemp -d)"
trap 'rm -f "$work_dir/header" "$work_dir/metadata.json" "$work_dir/source.json" "$work_dir/payload.json" "$work_dir/policy.hcl"; rmdir "$work_dir"' EXIT

printf 'X-Vault-Token: %s\n' "$source_token" > "$work_dir/header"
curl --silent --show-error --fail -H "@$work_dir/header" \
  "${source_addr%/}/v1/$metadata_path" > "$work_dir/metadata.json"
if ! jq -e \
  '[.data.versions[] | select(.destroyed or .deletion_time != "")] | length == 0' \
  "$work_dir/metadata.json" >/dev/null; then
  printf 'Source has deleted/destroyed versions; migration stopped to avoid changing version identifiers.\n' >&2
  exit 1
fi
status="$(kubectl -n vault exec vault-0 -- sh -c 'vault status -format=json; code=$?; test "$code" -eq 0 -o "$code" -eq 2')"
if [[ "$(printf '%s' "$status" | jq -r .initialized)" == false ]]; then
  if [[ -e "$LOCAL_DIR/init.json" ]]; then
    printf 'Initialization file already exists for an uninitialized Vault; refusing to overwrite it.\n' >&2
    exit 1
  fi
  kubectl -n vault exec vault-0 -- vault operator init \
    -key-shares=1 -key-threshold=1 -format=json > "$LOCAL_DIR/init.json"
fi
"$SCRIPT_DIR/unseal.sh"

mounts="$(admin /dev/null secrets list -format=json)"
if printf '%s' "$mounts" | jq -e 'has("secret/")' >/dev/null; then
  printf 'Destination secret mount already exists; refusing to overwrite a prior migration.\n' >&2
  exit 1
fi
admin /dev/null secrets enable -path=secret kv-v2 >/dev/null
retained_versions="$(jq -er '[(.data.versions | length), (.data.max_versions // 0), 10] | max' "$work_dir/metadata.json")"
admin /dev/null write secret/config max_versions="$retained_versions" >/dev/null
i=0
while IFS= read -r source_version; do
  curl --silent --show-error --fail -H "@$work_dir/header" \
    "${source_addr%/}/v1/$secret_path?version=$source_version" > "$work_dir/source.json"
  jq --argjson cas "$i" '{options:{cas:$cas},data:.data.data}' \
    "$work_dir/source.json" > "$work_dir/payload.json"
  admin "$work_dir/payload.json" write "$secret_path" - >/dev/null
  i=$((i+1))
  printf 'Migrated source version %s to destination version %s.\n' "$source_version" "$i"
done < <(jq -r '.data.versions | keys | map(tonumber) | sort | .[]' "$work_dir/metadata.json")

admin /dev/null kv metadata get -format=json "secret/${secret_path#secret/data/}" |
  jq -e --argjson count "$i" \
    '.data.current_version == $count and
    ([.data.versions[] | select(.destroyed == false and .deletion_time == "")] | length) == $count' \
    >/dev/null
configure_application_tokens
printf 'Migrated %s retained versions at %s; version identifiers and creation timestamps are new. Source Vault was not changed.\n' "$i" "$secret_path"
printf 'Sensitive initialization and token files are stored in vault/.local (Git-ignored).\n'
