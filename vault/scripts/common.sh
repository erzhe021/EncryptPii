#!/usr/bin/env bash

vault_exec() {
  local token="$1" input="$2"
  shift 2
  { printf '%s\n' "$token"; cat "$input"; } |
    kubectl -n vault exec -i vault-0 -- sh -c \
      'IFS= read -r VAULT_TOKEN; export VAULT_TOKEN; exec vault "$@"' sh "$@"
}

admin() {
  local input="$1" token
  shift
  token="$(jq -er '.root_token' "$LOCAL_DIR/init.json")" || return
  vault_exec "$token" "$input" "$@"
}

configure_application_tokens() {
  printf 'path "%s" { capabilities = ["read"] }\npath "%s" { capabilities = ["read"] }\n' \
    "$secret_path" "$metadata_path" |
    admin /dev/stdin policy write encryptpii-kong - >/dev/null
  printf 'path "%s" { capabilities = ["read", "update"] }\n' "$secret_path" |
    admin /dev/stdin policy write encryptpii-rotation - >/dev/null
  local role
  for role in kong rotation; do
    if [[ ! -s "$LOCAL_DIR/$role-token" ]]; then
      admin /dev/null token create -policy="encryptpii-$role" -orphan -ttl=720h -format=json \
        > "$LOCAL_DIR/$role-token.json"
      jq -jer '.auth.client_token' "$LOCAL_DIR/$role-token.json" > "$LOCAL_DIR/$role-token"
    fi
    vault_exec "$(cat "$LOCAL_DIR/$role-token")" /dev/null token lookup -format=json >/dev/null
  done
  kubectl create namespace kong --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n kong create secret generic encryptpii-vault \
    --from-file=token="$LOCAL_DIR/kong-token" --dry-run=client -o yaml | kubectl apply -f -
}
