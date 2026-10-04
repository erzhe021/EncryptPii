#!/usr/bin/env bash

load_plugin_env() {
  local env_file="$1"
  local line name value

  if [[ ! -f "$env_file" ]]; then
    printf 'Missing %s. Copy the repository-root .env.example to .env and configure the required values.\n' "$env_file" >&2
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
      KONG_TO_ENCRYPTPII_AUTH_TOKEN|KONG_TLS_CERT_FILE|KONG_TLS_KEY_FILE|KONG_ADMIN_URL|KONG_ADMIN_GUI_URL|KONG_ADMIN_GUI_API_URL|ENCRYPTPII_UPSTREAM_URL|ENCRYPTPII_VAULT_ADDR|ENCRYPTPII_VAULT_SECRET_PATH|ENCRYPTPII_KEY_ALIAS|ENCRYPTPII_KEY_VALIDITY_MILLIS|ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS|ENCRYPTPII_MAX_BODY_BYTES)
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

validate_gateway_token() {
  local token="${KONG_TO_ENCRYPTPII_AUTH_TOKEN:-}"
  if [[ "${#token}" -lt 32 || "$token" == replace-with-* || "$token" == *$'\n'* || "$token" == *$'\r'* ]]; then
    printf 'KONG_TO_ENCRYPTPII_AUTH_TOKEN 必须是至少 32 字符的有效密钥（环境变量或根目录 .env）。\n' >&2
    return 1
  fi
}

validate_crypto_config() {
  if [[ ! "${ENCRYPTPII_VAULT_SECRET_PATH:-}" =~ ^secret/data/[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$ ||
    ! "${ENCRYPTPII_KEY_ALIAS:-}" =~ ^[A-Za-z0-9_-]+$ ||
    "${ENCRYPTPII_KEY_ALIAS:-}" == replace-with-* ]]; then
    printf '根目录 .env 中的 Vault 密钥路径或别名无效。\n' >&2
    return 1
  fi
  local setting value minimum maximum
  for setting in ENCRYPTPII_KEY_VALIDITY_MILLIS ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS ENCRYPTPII_MAX_BODY_BYTES; do
    value="${!setting:-}"
    minimum=1
    maximum=31536000000
    [[ "$setting" != ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS ]] || minimum=0
    [[ "$setting" != ENCRYPTPII_MAX_BODY_BYTES ]] || maximum=16777216
    if [[ ! "$value" =~ ^(0|[1-9][0-9]*)$ || ${#value} -gt 11 ]]; then
      printf '%s 必须是范围 %s–%s 内的整数。\n' "$setting" "$minimum" "$maximum" >&2
      return 1
    fi
    if ((value < minimum || value > maximum)); then
      printf '%s 必须是范围 %s–%s 内的整数。\n' "$setting" "$minimum" "$maximum" >&2
      return 1
    fi
  done
}
