#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
component="${1:-}"
case "$component" in
  client|server|vault) component_dir="$component" ;;
  kong) component_dir=sensitive-transport-crypto ;;
  *)
    printf '用法: scripts/delete-k8s-component.sh {client|server|kong|vault} [--yes] [--purge-data]\n' >&2
    exit 2
    ;;
esac
shift
exec bash "$REPO_DIR/$component_dir/scripts/delete-from-k8s.sh" "$@"
