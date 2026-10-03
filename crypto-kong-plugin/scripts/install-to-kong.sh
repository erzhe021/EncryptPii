#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$PLUGIN_DIR/docker-compose.yml"
ENV_FILE="$PLUGIN_DIR/.env"
ADMIN_URL="${KONG_ADMIN_URL:-http://localhost:8001}"

for command in docker curl jq; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'Required command not found: %s\n' "$command" >&2
    exit 1
  fi
done

if [[ ! -f "$ENV_FILE" ]]; then
  printf 'Missing %s. Copy .env.example to .env and configure both secret values.\n' "$ENV_FILE" >&2
  exit 1
fi
if ! grep -Eq '^ENCRYPTPII_VAULT_TOKEN=.+$' "$ENV_FILE"; then
  printf 'ENCRYPTPII_VAULT_TOKEN must be set in %s\n' "$ENV_FILE" >&2
  exit 1
fi
if ! grep -Eq '^ENCRYPTPII_GATEWAY_TOKEN=.{32,}$' "$ENV_FILE"; then
  printf 'Set ENCRYPTPII_GATEWAY_TOKEN to a random value of at least 32 characters in %s\n' "$ENV_FILE" >&2
  exit 1
fi
if grep -Eq '^ENCRYPTPII_GATEWAY_TOKEN=(replace-with-|$)' "$ENV_FILE"; then
  printf 'Replace the example gateway token in %s before installation\n' "$ENV_FILE" >&2
  exit 1
fi

docker compose --project-directory "$PLUGIN_DIR" -f "$COMPOSE_FILE" up -d --build kong

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
  jq -e '.enabled_plugins | index("crypto-kong-plugin") != null' >/dev/null; then
  printf 'Kong is running but crypto-kong-plugin is not enabled\n' >&2
  exit 1
fi

KONG_ADMIN_URL="$ADMIN_URL" "$SCRIPT_DIR/configure-routes.sh"

printf 'Plugin installed. Proxy: http://localhost:8000; Kong Admin API: %s\n' "$ADMIN_URL"
