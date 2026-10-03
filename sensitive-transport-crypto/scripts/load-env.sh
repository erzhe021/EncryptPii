#!/usr/bin/env bash

load_plugin_env() {
  local env_file="$1"
  local line name value

  if [[ ! -f "$env_file" ]]; then
    printf 'Missing %s. Copy .env.example to .env and configure the required values.\n' "$env_file" >&2
    return 1
  fi

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    if [[ ! "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=(.*)$ ]]; then
      continue
    fi
    name="${BASH_REMATCH[2]}"
    value="${BASH_REMATCH[3]}"
    case "$name" in
      KONG_ADMIN_URL|KONG_ADMIN_GUI_URL|KONG_ADMIN_GUI_API_URL|ENCRYPTPII_VAULT_TOKEN|ENCRYPTPII_GATEWAY_TOKEN|ENCRYPTPII_UPSTREAM_URL|ENCRYPTPII_VAULT_ADDR|ENCRYPTPII_VAULT_SECRET_PATH|ENCRYPTPII_KEY_ALIAS|ENCRYPTPII_KEY_VALIDITY_MILLIS|ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS|ENCRYPTPII_MAX_BODY_BYTES)
        if printenv "$name" >/dev/null; then
          continue
        fi
        ;;
      *) continue ;;
    esac

    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    if [[ "$value" == \"*\" || "$value" == \'*\' ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "$value" == \"* || "$value" == \'* ]]; then
      printf 'Unterminated quoted value for %s in %s\n' "$name" "$env_file" >&2
      return 1
    else
      value="${value%%[[:space:]]#*}"
      value="${value%"${value##*[![:space:]]}"}"
    fi
    export "$name=$value"
  done < "$env_file"
}
