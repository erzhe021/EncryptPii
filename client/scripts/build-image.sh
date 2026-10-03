#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
"$REPO_DIR/gradlew" -p "$REPO_DIR" :client:bootJar
docker build -t encryptpii-client:local "$REPO_DIR/client"
