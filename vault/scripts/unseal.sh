#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INIT_FILE="$SCRIPT_DIR/../.local/init.json"
if [[ ! -f "$INIT_FILE" ]]; then
  printf 'Missing Vault initialization credentials: %s\n' "$INIT_FILE" >&2
  exit 1
fi
jq -er '.unseal_keys_b64[0]' "$INIT_FILE" |
  kubectl -n vault exec -i vault-0 -- sh -c 'IFS= read -r key; vault operator unseal "$key" >/dev/null'
kubectl -n vault wait --for=condition=Ready pod/vault-0 --timeout=60s
