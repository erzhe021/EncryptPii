#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
KONG_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd -- "$KONG_DIR/.." && pwd)"
COMPOSE_FILE="$KONG_DIR/docker-compose.yml"
ENV_FILE="$REPO_DIR/.env"
source "$SCRIPT_DIR/load-env.sh"
load_plugin_env "$ENV_FILE"

docker compose --env-file "$ENV_FILE" --project-directory "$KONG_DIR" -f "$COMPOSE_FILE" build kong

docker run --rm \
  --mount "type=bind,source=$KONG_DIR/tests,target=/tmp/plugin-tests,readonly" \
  -e KONG_DATABASE=off \
  -e KONG_PLUGINS=bundled,sensitive-transport-crypto \
  encryptpii-kong:3.7 kong config parse /tmp/plugin-tests/kong-parity.yaml >/dev/null

docker run --rm \
  --entrypoint /usr/local/openresty/luajit/bin/luajit \
  encryptpii-kong:3.7 \
  -e '
    local files = {
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/handler.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/access.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/response.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/errors.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/protocol.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/payload.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/size_limit.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/key_cache.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/key_parser.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/key_version_policy.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/vault_auth.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/vault_location.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/vault_request.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/vault.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/keys.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/crypto.lua",
      "/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/schema.lua",
    }
    for _, file in ipairs(files) do
      local chunk, err = loadfile(file)
      assert(chunk, file .. ": " .. tostring(err))
    end
    print("Kong plugin Lua files compile successfully")
  '

docker run --rm \
  --mount "type=bind,source=$KONG_DIR/tests,target=/tmp/plugin-tests,readonly" \
  -e 'LUA_CPATH=/usr/local/openresty/lualib/?.so;;' \
  --entrypoint /usr/local/openresty/luajit/bin/luajit \
  encryptpii-kong:3.7 \
  /tmp/plugin-tests/key-cache-test.lua

docker run --rm \
  --mount "type=bind,source=$KONG_DIR/tests,target=/tmp/plugin-tests,readonly" \
  -e 'LUA_CPATH=/usr/local/openresty/lualib/?.so;;' \
  --entrypoint /usr/local/openresty/luajit/bin/luajit \
  encryptpii-kong:3.7 \
  /tmp/plugin-tests/size-limit-log-test.lua

docker run --rm \
  --mount "type=bind,source=$KONG_DIR/tests,target=/tmp/plugin-tests,readonly" \
  -e 'LUA_CPATH=/usr/local/openresty/lualib/?.so;;' \
  --entrypoint /usr/local/openresty/luajit/bin/luajit \
  encryptpii-kong:3.7 \
  /tmp/plugin-tests/header-transport-test.lua

docker run --rm \
  --mount "type=bind,source=$KONG_DIR/tests,target=/tmp/plugin-tests,readonly" \
  -e 'LUA_CPATH=/usr/local/openresty/lualib/?.so;;' \
  --entrypoint /usr/local/openresty/luajit/bin/luajit \
  encryptpii-kong:3.7 \
  /tmp/plugin-tests/payload-test.lua

docker run --rm \
  --mount "type=bind,source=$KONG_DIR/tests,target=/tmp/plugin-tests,readonly" \
  -e 'LUA_CPATH=/usr/local/openresty/lualib/?.so;;' \
  --entrypoint /usr/local/openresty/luajit/bin/luajit \
  encryptpii-kong:3.7 \
  /tmp/plugin-tests/key-resolution-test.lua

docker run --rm \
  --mount "type=bind,source=$KONG_DIR/tests,target=/tmp/plugin-tests,readonly" \
  -e 'LUA_CPATH=/usr/local/openresty/lualib/?.so;;' \
  --entrypoint /usr/local/openresty/luajit/bin/luajit \
  encryptpii-kong:3.7 \
  /tmp/plugin-tests/response-test.lua

docker run --rm \
  --mount "type=bind,source=$KONG_DIR/tests,target=/tmp/plugin-tests,readonly" \
  --entrypoint /usr/local/openresty/bin/resty \
  encryptpii-kong:3.7 \
  /tmp/plugin-tests/crypto-real-test.lua
