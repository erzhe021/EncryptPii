#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd -- "$PLUGIN_DIR/.." && pwd)"
ENV_FILE="$REPO_DIR/.env"

source "$SCRIPT_DIR/load-env.sh"
if [[ -f "$ENV_FILE" ]]; then
  load_plugin_env "$ENV_FILE"
fi
validate_crypto_config

ADMIN_URL="${KONG_ADMIN_URL:?Please set the KONG_ADMIN_URL environment variable}"
UPSTREAM_URL="${ENCRYPTPII_UPSTREAM_URL:?Please set the ENCRYPTPII_UPSTREAM_URL environment variable}"
VAULT_ADDR="${ENCRYPTPII_VAULT_ADDR:?Please set the ENCRYPTPII_VAULT_ADDR environment variable}"
VAULT_SECRET_PATH="${ENCRYPTPII_VAULT_SECRET_PATH:?Please set the ENCRYPTPII_VAULT_SECRET_PATH environment variable}"
KEY_ALIAS="${ENCRYPTPII_KEY_ALIAS:?Please set the ENCRYPTPII_KEY_ALIAS environment variable}"
KEY_VALIDITY_MILLIS="${ENCRYPTPII_KEY_VALIDITY_MILLIS:?Please set the ENCRYPTPII_KEY_VALIDITY_MILLIS environment variable}"
KEY_GRACE_PERIOD_MILLIS="${ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS:?Please set the ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS environment variable}"
MAX_BODY_BYTES="${ENCRYPTPII_MAX_BODY_BYTES:?Please set the ENCRYPTPII_MAX_BODY_BYTES environment variable}"

for command in curl jq; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'Required command not found: %s\n' "$command" >&2
    exit 1
  fi
done

if [[ ! "$UPSTREAM_URL" =~ ^https?://[^/]+$ ]]; then
  printf 'ENCRYPTPII_UPSTREAM_URL must be an HTTP(S) origin without a path\n' >&2
  exit 1
fi

api() {
  curl --silent --show-error --fail-with-body "$@"
}

service_json="$(jq -n --arg url "$UPSTREAM_URL" '{name:"encryptpii-server",url:$url}')"
existing_service_id="$(
  api "$ADMIN_URL/services?size=1000" |
    jq -r '.data[] | select(.name == "encryptpii-server") | .id' |
    head -n 1
)"
if [[ -n "$existing_service_id" ]]; then
  api -X PUT "$ADMIN_URL/services/$existing_service_id" \
    -H 'Content-Type: application/json' \
    --data-binary "$service_json" >/dev/null
else
  api -X POST "$ADMIN_URL/services" \
    -H 'Content-Type: application/json' \
    --data-binary "$service_json" >/dev/null
fi

service_id="$(
  api "$ADMIN_URL/services?size=1000" |
    jq -r '.data[] | select(.name == "encryptpii-server") | .id' |
    head -n 1
)"
if [[ -z "$service_id" ]]; then
  printf 'Could not find the configured Kong upstream service\n' >&2
  exit 1
fi

upsert_route() {
  local name="$1"
  local path="$2"
  local method="$3"
  local route_id route_json

  route_json="$(
    jq -n \
      --arg name "$name" \
      --arg path "$path" \
      --arg method "$method" \
      --arg service_id "$service_id" \
      '{name:$name,paths:[$path],methods:[$method],strip_path:false,service:{id:$service_id}}'
  )"
  route_id="$(
    api "$ADMIN_URL/routes?size=1000" |
      jq -r --arg name "$name" '.data[] | select(.name == $name) | .id' |
      head -n 1
  )"

  if [[ -n "$route_id" ]]; then
    api -X PUT "$ADMIN_URL/routes/$route_id" \
      -H 'Content-Type: application/json' \
      --data-binary "$route_json" >/dev/null
  else
    api -X POST "$ADMIN_URL/services/$service_id/routes" \
      -H 'Content-Type: application/json' \
      --data-binary "$route_json" >/dev/null
  fi

  api "$ADMIN_URL/routes?size=1000" |
    jq -r --arg name "$name" '.data[] | select(.name == $name) | .id' |
    head -n 1
}

upsert_plugin() {
  local route_id="$1"
  local decrypt_request="$2"
  local encrypt_response="$3"
  local session_key_source="$4"
  local upstream_path="$5"
  local serve_public_key="${6:-false}"
  local config plugin_json existing_plugin_id

  config="$(
    jq -n \
      --arg vault_addr "$VAULT_ADDR" \
      --arg vault_secret_path "$VAULT_SECRET_PATH" \
      --arg key_alias "$KEY_ALIAS" \
      --arg upstream_path "$upstream_path" \
      --argjson key_validity_millis "$KEY_VALIDITY_MILLIS" \
      --argjson key_grace_period_millis "$KEY_GRACE_PERIOD_MILLIS" \
      --argjson max_body_bytes "$MAX_BODY_BYTES" \
      --argjson decrypt_request "$decrypt_request" \
      --argjson encrypt_response "$encrypt_response" \
      --argjson serve_public_key "$serve_public_key" \
      --arg session_key_source "$session_key_source" \
      '{
        vault_addr:$vault_addr,
        vault_token:"{vault://env/ENCRYPTPII_VAULT_TOKEN}",
        vault_secret_path:$vault_secret_path,
        key_alias:$key_alias,
        key_validity_millis:$key_validity_millis,
        key_grace_period_millis:$key_grace_period_millis,
        upstream_path:$upstream_path,
        upstream_auth_token:"{vault://env/ENCRYPTPII_GATEWAY_TOKEN}",
        decrypt_request:$decrypt_request,
        encrypt_response:$encrypt_response,
        serve_public_key:$serve_public_key,
        session_key_source:$session_key_source,
        max_body_bytes:$max_body_bytes
      }'
  )"
  plugin_json="$(
    jq -n --arg route_id "$route_id" --argjson config "$config" \
      '{name:"sensitive-transport-crypto",route:{id:$route_id},config:$config}'
  )"

  existing_plugin_id="$(
    api "$ADMIN_URL/routes/$route_id/plugins?size=1000" |
      jq -r '.data[] | select(.name == "sensitive-transport-crypto") | .id' |
      head -n 1
  )"
  if [[ -n "$existing_plugin_id" ]]; then
    api -X PUT "$ADMIN_URL/plugins/$existing_plugin_id" \
      -H 'Content-Type: application/json' \
      --data-binary "$plugin_json" >/dev/null
  else
    api -X POST "$ADMIN_URL/routes/$route_id/plugins" \
      -H 'Content-Type: application/json' \
      --data-binary "$plugin_json" >/dev/null
  fi
}

public_key_route="$(
  upsert_route encryptpii-public-key /crypto/server/public-key GET
)"
bidirectional_route="$(
  upsert_route encryptpii-bidirectional /crypto/server/bidirectional POST
)"
request_only_route="$(
  upsert_route encryptpii-request-only /crypto/server/request-only POST
)"
response_only_route="$(
  upsert_route encryptpii-response-only /crypto/server/response-only POST
)"

upsert_plugin "$bidirectional_route" true true body /crypto/kong/bidirectional
upsert_plugin "$request_only_route" true false body /crypto/kong/request-only
upsert_plugin "$response_only_route" false true header /crypto/kong/response-only
upsert_plugin "$public_key_route" false false body /crypto/server/public-key true

api -X PUT "$ADMIN_URL/services/encryptpii-server-plain" \
  -H 'Content-Type: application/json' \
  --data-binary "$(jq -n --arg url "$UPSTREAM_URL" \
    '{name:"encryptpii-server-plain",url:$url}')" >/dev/null
api -X PUT "$ADMIN_URL/routes/encryptpii-plain" \
  -H 'Content-Type: application/json' \
  --data-binary '{
    "name":"encryptpii-plain",
    "service":{"name":"encryptpii-server-plain"},
    "paths":["/plain/server/normal"],
    "methods":["POST"],
    "strip_path":false,
    "path_handling":"v0"
  }' >/dev/null

printf 'Configured the Vault-backed public-key route, three protected crypto routes, and a plugin-free plaintext route. ADMIN URL: %s\n' "$ADMIN_URL"
