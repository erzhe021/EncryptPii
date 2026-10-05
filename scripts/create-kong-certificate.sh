#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
CERT_DIR="$REPO_DIR/certs"
force=false
directory_set=false

usage() {
  printf '用法: scripts/create-kong-certificate.sh [--force] [证书目录]\n'
  printf '生成有效期 365 天、SAN 包含 localhost 和 local.kong.test 的 Kong 自签名证书。\n'
  printf '默认保存到仓库 certs/；--force 允许替换已有证书和私钥。\n'
}

for argument in "$@"; do
  case "$argument" in
    --help|-h) usage; exit 0 ;;
    --force) force=true ;;
    -*)
      printf '未知参数: %s\n' "$argument" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ "$directory_set" == true ]]; then
        usage >&2
        exit 2
      fi
      CERT_DIR="$argument"
      directory_set=true
      ;;
  esac
done

if ! command -v openssl >/dev/null 2>&1; then
  printf '缺少命令: openssl\n' >&2
  exit 1
fi

if [[ "$force" != true && ( -e "$CERT_DIR/kong.crt" || -e "$CERT_DIR/kong.key" ) ]]; then
  printf '证书或私钥已存在: %s\n如需重新签发，请使用 --force。\n' "$CERT_DIR" >&2
  exit 1
fi

mkdir -p -- "$CERT_DIR"
work_dir="$(mktemp -d "$CERT_DIR/.kong-cert-XXXXXXXX")"
cleanup() {
  rm -f "$work_dir/kong.crt" "$work_dir/kong.key"
  rmdir "$work_dir"
}
trap cleanup EXIT

openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
  -keyout "$work_dir/kong.key" -out "$work_dir/kong.crt" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:local.kong.test"
openssl verify -CAfile "$work_dir/kong.crt" "$work_dir/kong.crt"

cp "$work_dir/kong.key" "$CERT_DIR/kong.key"
chmod 600 "$CERT_DIR/kong.key"
cp "$work_dir/kong.crt" "$CERT_DIR/kong.crt"
printf '已生成 Kong 证书: %s/kong.crt\n私钥: %s/kong.key\n' "$CERT_DIR" "$CERT_DIR"
printf '若 Kong 已部署，请更新 TLS Secret 并重启 Kong；已使用旧证书的客户端需按需更新信任配置。\n'
