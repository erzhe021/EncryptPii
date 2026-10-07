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
if [[ -z "${KONG_TLS_CERT_FILE:-}" || -z "${KONG_TLS_KEY_FILE:-}" ]]; then
  printf 'KONG_TLS_CERT_FILE 和 KONG_TLS_KEY_FILE 必须在根目录 .env 中配置。\n' >&2
  exit 1
fi
tls_cert_file="$KONG_TLS_CERT_FILE"
tls_key_file="$KONG_TLS_KEY_FILE"
[[ "$tls_cert_file" = /* ]] || tls_cert_file="$REPO_DIR/$tls_cert_file"
[[ "$tls_key_file" = /* ]] || tls_key_file="$REPO_DIR/$tls_key_file"
if [[ "$(kubectl config current-context)" != "docker-desktop" ]]; then
  printf 'This local deployment script requires the docker-desktop context.\n' >&2
  exit 1
fi
if [[ "$tls_cert_file" == "$REPO_DIR/certs/kong.crt" &&
      "$tls_key_file" == "$REPO_DIR/certs/kong.key" &&
      ! -e "$tls_cert_file" && ! -L "$tls_cert_file" &&
      ! -e "$tls_key_file" && ! -L "$tls_key_file" ]]; then
  printf '默认 Kong TLS 证书和私钥均不存在，正在生成本地自签名证书。\n'
  bash "$REPO_DIR/scripts/create-kong-certificate.sh"
fi
if [[ ! -f "$tls_cert_file" || ! -f "$tls_key_file" ]]; then
  printf '找不到 TLS 证书或私钥文件：请检查 KONG_TLS_CERT_FILE 和 KONG_TLS_KEY_FILE。仅默认路径的两个文件均不存在时才会自动生成。\n' >&2
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
kubectl -n kong create secret tls encryptpii-kong-tls \
  --cert="$tls_cert_file" --key="$tls_key_file" \
  --dry-run=client -o yaml | kubectl apply -f -
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
  def plugin($public; $decrypt; $encrypt; $path):
    {name:"sensitive-transport-crypto",config:{
      vault_addr:$vault_addr,vault_secret_path:$secret_path,key_alias:$alias,
      vault_auth_role:"encryptpii-kong",
      upstream_auth_token:"{vault://env/KONG_TO_ENCRYPTPII_AUTH_TOKEN}",
      key_validity_millis:$validity,key_grace_period_millis:$grace,
      max_body_bytes:$max_body,serve_public_key:$public,
      decrypt_request:$decrypt,encrypt_response:$encrypt,
      upstream_path:$path}};
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
         strip_path:false,plugins:[plugin(true;false;false;"/crypto/server/public-key")]},
        {name:"encryptpii-bidirectional",paths:["/crypto/server/bidirectional"],methods:["POST"],
         strip_path:false,plugins:[plugin(false;true;true;"/crypto/server/bidirectional")]},
        {name:"encryptpii-request-only",paths:["/crypto/server/request-only"],methods:["POST"],
         strip_path:false,plugins:[plugin(false;true;false;"/crypto/server/request-only")]},
        {name:"encryptpii-response-only",paths:["/crypto/server/response-only"],methods:["POST"],
         strip_path:false,plugins:[plugin(false;false;true;"/crypto/server/response-only")]},
        (["client-exception","system-exception","business-exception"][] as $exception |
         ("/crypto/server/response-only/" + $exception) as $path |
         {name:("encryptpii-response-only-" + $exception),paths:[$path],methods:["POST"],
          strip_path:false,plugins:[plugin(false;false;true;$path)]})
      ]
    }]
  }' > "$work_dir/kong.json"
kubectl -n kong create configmap encryptpii-kong-config \
  --from-file=kong.json="$work_dir/kong.json" --dry-run=client -o yaml | kubectl apply -f -

"$REPO_DIR/scripts/import-local-k8s-images.sh" encryptpii-kong:3.7

kubectl apply -f "$KONG_DIR/k8s/kong.yaml"
kubectl -n kong rollout restart deployment/encryptpii-kong
kubectl -n kong rollout status deployment/encryptpii-kong --timeout=180s
printf 'Kong deployed. Access with: kubectl -n kong port-forward service/encryptpii-kong 18443:8443 18000:8000 18001:8001 18002:8002\n'
