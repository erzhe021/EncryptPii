#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '用法: scripts/trust-mitmproxy-certificate.sh\n'
  printf '将 ~/.mitmproxy/mitmproxy-ca-cert.pem 加入 macOS 系统钥匙串并信任。\n'
}

if [[ "$#" -eq 1 && "$1" =~ ^(-h|--help)$ ]]; then
  usage
  exit 0
fi

if [[ "$#" -ne 0 ]]; then
  usage >&2
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

CERT_FILE="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
if [[ ! -f "$CERT_FILE" ]]; then
  printf '找不到 mitmproxy CA 证书: %s\n请先启动 mitmweb 或 mitmproxy 生成证书。\n' "$CERT_FILE" >&2
  exit 1
fi

if ! openssl x509 -in "$CERT_FILE" -noout >/dev/null 2>&1; then
  printf '不是有效的 PEM X.509 证书: %s\n' "$CERT_FILE" >&2
  exit 1
fi

if ! openssl x509 -in "$CERT_FILE" -noout -text | grep -F 'CA:TRUE' >/dev/null; then
  printf '证书不是 CA 证书: %s\n' "$CERT_FILE" >&2
  exit 1
fi

if ! openssl x509 -in "$CERT_FILE" -noout -checkend 0 >/dev/null; then
  printf 'mitmproxy CA 证书已过期: %s\n' "$CERT_FILE" >&2
  exit 1
fi

printf '即将把此 mitmproxy CA 证书加入 macOS 系统钥匙串并设为受信任根证书：\n%s\n' "$CERT_FILE"
openssl x509 -in "$CERT_FILE" -noout -subject -fingerprint -sha256
printf '仅信任你确认来源可信的本机证书；此操作需要管理员授权。\n'
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain "$CERT_FILE"
printf '已信任 mitmproxy CA 证书。请重启微信开发者工具或其他使用代理的应用。\n'
