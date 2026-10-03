#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$PLUGIN_DIR/docker-compose.yml"
ENV_FILE="$PLUGIN_DIR/.env"
source "$SCRIPT_DIR/load-env.sh"
load_plugin_env "$ENV_FILE"

docker compose --env-file "$ENV_FILE" --project-directory "$PLUGIN_DIR" -f "$COMPOSE_FILE" build kong

docker run --rm \
  --entrypoint /usr/local/openresty/luajit/bin/luajit \
  encryptpii-kong:3.7 \
  -e '
    local files = {
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/handler.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/schema.lua",
    }
    for _, file in ipairs(files) do
      local chunk, err = loadfile(file)
      assert(chunk, file .. ": " .. tostring(err))
    end
    print("Kong plugin Lua files compile successfully")
  '
