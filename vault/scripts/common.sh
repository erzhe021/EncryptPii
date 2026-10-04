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
    admin /dev/stdin policy write encryptpii-kong-k8s - >/dev/null
  printf 'path "%s" { capabilities = ["read"] }\npath "%s" { capabilities = ["read"] }\n' \
    "$secret_path" "$metadata_path" |
    admin /dev/stdin policy write encryptpii-kong - >/dev/null
  printf 'path "%s" { capabilities = ["read", "update"] }\n' "$secret_path" |
    admin /dev/stdin policy write encryptpii-rotation - >/dev/null

  kubectl create namespace kong --dry-run=client -o yaml | kubectl apply -f -
  kubectl -n kong create serviceaccount encryptpii-kong --dry-run=client -o yaml |
    kubectl apply -f -

  local auth_mounts
  auth_mounts="$(admin /dev/null auth list -format=json)"
  if ! printf '%s' "$auth_mounts" | jq -e 'has("kubernetes/")' >/dev/null; then
    admin /dev/null auth enable kubernetes >/dev/null
  elif ! printf '%s' "$auth_mounts" |
    jq -e '."kubernetes/".type == "kubernetes"' >/dev/null; then
    printf 'Vault auth/kubernetes is mounted with an unexpected type.\n' >&2
    return 1
  fi
  admin /dev/null write auth/kubernetes/config \
    kubernetes_host=https://kubernetes.default.svc:443 \
    kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt >/dev/null
  admin /dev/null write auth/kubernetes/role/encryptpii-kong \
    bound_service_account_names=encryptpii-kong \
    bound_service_account_namespaces=kong \
    policies=encryptpii-kong-k8s \
    ttl=1h >/dev/null

  if [[ ! -s "$LOCAL_DIR/rotation-token" ]]; then
    admin /dev/null token create -policy=encryptpii-rotation -orphan -ttl=720h -format=json \
      > "$LOCAL_DIR/rotation-token.json"
    jq -jer '.auth.client_token' "$LOCAL_DIR/rotation-token.json" > "$LOCAL_DIR/rotation-token"
  fi
  vault_exec "$(cat "$LOCAL_DIR/rotation-token")" /dev/null token lookup -format=json >/dev/null
  kubectl -n kong delete secret encryptpii-vault --ignore-not-found=true >/dev/null
}
