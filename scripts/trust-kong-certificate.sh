#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
CERT_FILE="${1:-$REPO_DIR/certs/kong.crt}"

if [[ "$#" -eq 1 && "$1" =~ ^(-h|--help)$ ]]; then
  printf '用法: scripts/trust-kong-certificate.sh [证书文件]\n'
  printf '将 Kong 自签名证书加入 macOS 系统钥匙串并设为受信任根证书。\n'
  exit 0
fi

if [[ "$#" -gt 1 ]]; then
  printf '用法: scripts/trust-kong-certificate.sh [证书文件]\n' >&2
  exit 2
fi

if [[ "$(uname -s)" != Darwin ]]; then
  printf '此脚本仅支持 macOS。\n' >&2
  exit 1
fi

for command in openssl security sudo; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf '缺少命令: %s\n' "$command" >&2
    exit 1
  fi
done

if [[ ! -f "$CERT_FILE" ]]; then
  printf '找不到 Kong 证书: %s\n' "$CERT_FILE" >&2
  exit 1
fi

if ! openssl x509 -in "$CERT_FILE" -noout >/dev/null 2>&1; then
  printf '不是有效的 PEM X.509 证书: %s\n' "$CERT_FILE" >&2
  exit 1
fi

if ! openssl x509 -in "$CERT_FILE" -noout -text | grep -F 'DNS:local.kong.test' >/dev/null; then
  printf '证书 SAN 中不包含 DNS:local.kong.test: %s\n' "$CERT_FILE" >&2
  exit 1
fi

printf '即将把此 Kong 自签名证书加入 macOS 系统钥匙串并设为受信任根证书：\n%s\n' "$CERT_FILE"
printf '仅信任你确认来源可信的证书；此操作需要管理员授权。\n'
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain "$CERT_FILE"
printf '已信任 Kong 证书。若相关应用仍缓存旧的 TLS 状态，请重启应用。\n'
