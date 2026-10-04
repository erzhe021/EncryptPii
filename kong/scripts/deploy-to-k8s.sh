#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
KONG_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd -- "$KONG_DIR/.." && pwd)"
skip_build=false
for argument in "$@"; do
  case "$argument" in
    --help|-h)
      printf '用法: kong/scripts/deploy-to-k8s.sh [--skip-build]\n默认使用 Kubernetes auth 访问集群内 Vault。\n'
      exit 0 ;;
    --vault-in-k8s) ;; # Compatible with older deployment commands.
    --skip-build) skip_build=true ;;
    *) printf '未知参数：%s\n' "$argument" >&2; exit 2 ;;
  esac
done
source "$SCRIPT_DIR/load-env.sh"
load_plugin_env "$REPO_DIR/.env"
validate_crypto_config
if [[ "$(kubectl config current-context)" != "docker-desktop" ]]; then
  printf 'This local deployment script requires the docker-desktop context.\n' >&2
  exit 1
fi
kubectl -n encryptpii get secret encryptpii-gateway >/dev/null
if [[ "$skip_build" != true ]]; then
  "$SCRIPT_DIR/build-plugin.sh"
fi

work_dir="$(mktemp -d)"
cleanup() {
  rm -f "$work_dir/kong.json"
  rmdir "$work_dir"
}
trap cleanup EXIT

kubectl create namespace kong --dry-run=client -o yaml | kubectl apply -f -
kubectl -n encryptpii get secret encryptpii-gateway -o json |
  jq '{apiVersion:"v1",kind:"Secret",metadata:{name:"encryptpii-gateway",namespace:"kong"},type:.type,data:.data}' |
  kubectl apply -f -

jq -n \
  --arg vault_addr "http://vault.vault.svc.cluster.local:8200" \
  --arg secret_path "${ENCRYPTPII_VAULT_SECRET_PATH:?}" \
  --arg alias "${ENCRYPTPII_KEY_ALIAS:?}" \
  --argjson validity "${ENCRYPTPII_KEY_VALIDITY_MILLIS:?}" \
  --argjson grace "${ENCRYPTPII_KEY_GRACE_PERIOD_MILLIS:?}" \
  --argjson max_body "${ENCRYPTPII_MAX_BODY_BYTES:?}" \
  '
  def plugin($public; $decrypt; $encrypt; $source; $path):
    {name:"sensitive-transport-crypto",config:{
      vault_addr:$vault_addr,vault_secret_path:$secret_path,key_alias:$alias,
      vault_auth_role:"encryptpii-kong",
      upstream_auth_token:"{vault://env/KONG_TO_ENCRYPTPII_AUTH_TOKEN}",
      key_validity_millis:$validity,key_grace_period_millis:$grace,
      max_body_bytes:$max_body,serve_public_key:$public,
      decrypt_request:$decrypt,encrypt_response:$encrypt,
      session_key_source:$source,upstream_path:$path}};
  {
    _format_version:"3.0",
    services:[{
      name:"encryptpii-server-plain",
      url:"http://encryptpii-server.encryptpii.svc.cluster.local:9090",
      routes:[{
        name:"encryptpii-plain",
        paths:["/plain/server/normal"],
        methods:["POST"],
        strip_path:false,
        path_handling:"v0"
      }]
    },{
      name:"encryptpii-server",
      url:"http://encryptpii-server.encryptpii.svc.cluster.local:9090",
      routes:[
        {name:"encryptpii-public-key",paths:["/crypto/server/public-key"],methods:["GET"],
         strip_path:false,plugins:[plugin(true;false;false;"body";"/crypto/server/public-key")]},
        {name:"encryptpii-bidirectional",paths:["/crypto/server/bidirectional"],methods:["POST"],
         strip_path:false,plugins:[plugin(false;true;true;"body";"/crypto/server/bidirectional")]},
        {name:"encryptpii-request-only",paths:["/crypto/server/request-only"],methods:["POST"],
         strip_path:false,plugins:[plugin(false;true;false;"body";"/crypto/server/request-only")]},
        {name:"encryptpii-response-only",paths:["/crypto/server/response-only"],methods:["POST"],
         strip_path:false,plugins:[plugin(false;false;true;"header";"/crypto/server/response-only")]}
      ]
    }]
  }' > "$work_dir/kong.json"
kubectl -n kong create configmap encryptpii-kong-config \
  --from-file=kong.json="$work_dir/kong.json" --dry-run=client -o yaml | kubectl apply -f -

"$REPO_DIR/scripts/import-local-k8s-images.sh" encryptpii-kong:3.7

kubectl apply -f "$KONG_DIR/k8s/kong.yaml"
kubectl -n kong rollout restart deployment/encryptpii-kong
kubectl -n kong rollout status deployment/encryptpii-kong --timeout=180s
printf 'Kong deployed. Access with: kubectl -n kong port-forward service/encryptpii-kong 18000:8000 18001:8001 18002:8002\n'
