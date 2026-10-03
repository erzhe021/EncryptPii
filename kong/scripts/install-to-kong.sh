#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
KONG_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd -- "$KONG_DIR/.." && pwd)"
COMPOSE_FILE="$KONG_DIR/docker-compose.yml"
ENV_FILE="$REPO_DIR/.env"
source "$SCRIPT_DIR/load-env.sh"
load_plugin_env "$ENV_FILE"
ADMIN_URL="${KONG_ADMIN_URL:?Please set the KONG_ADMIN_URL environment variable}"

for command in docker curl jq; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'Required command not found: %s\n' "$command" >&2
    exit 1
  fi
done

if [[ -z "${ENCRYPTPII_VAULT_TOKEN:-}" || "$ENCRYPTPII_VAULT_TOKEN" == replace-with-* ]]; then
  printf 'ENCRYPTPII_VAULT_TOKEN must be set in %s\n' "$ENV_FILE" >&2
  exit 1
fi
gateway_token="${ENCRYPTPII_GATEWAY_TOKEN:-}"
if [[ ${#gateway_token} -lt 32 ]]; then
  printf 'Set ENCRYPTPII_GATEWAY_TOKEN to a random value of at least 32 characters in %s\n' "$ENV_FILE" >&2
  exit 1
fi
if [[ "$ENCRYPTPII_GATEWAY_TOKEN" == replace-with-* ]]; then
  printf 'Replace the example gateway token in %s before installation\n' "$ENV_FILE" >&2
  exit 1
fi

docker compose --env-file "$ENV_FILE" --project-directory "$KONG_DIR" -f "$COMPOSE_FILE" up -d --build kong

for attempt in $(seq 1 60); do
  if curl --silent --fail "$ADMIN_URL/" >/dev/null; then
    break
  fi
  if [[ "$attempt" -eq 60 ]]; then
    printf 'Kong Admin API did not become available at %s\n' "$ADMIN_URL" >&2
    exit 1
  fi
  sleep 2
done

if ! curl --silent --show-error --fail "$ADMIN_URL/plugins/enabled" |
  jq -e '.enabled_plugins | index("sensitive-transport-crypto") != null' >/dev/null; then
  printf 'Kong is running but sensitive-transport-crypto is not enabled\n' >&2
  exit 1
fi

KONG_ADMIN_URL="$ADMIN_URL" "$SCRIPT_DIR/configure-routes.sh"

printf 'Plugin installed. Proxy: http://localhost:8000; Kong Admin API: %s\n' "$ADMIN_URL"
