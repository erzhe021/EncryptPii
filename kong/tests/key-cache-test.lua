local now = 1700000000
local current_version = 1
local created_time = os.date("!%Y-%m-%dT%H:%M:%SZ", now)
local version2_created_time = created_time
local reads = 0
local logins = 0
local login_status = 200
local jwt_path = "/test/serviceaccount/token"
local original_io_open = io.open
io.open = function(path, mode)
  if path == jwt_path then
    assert(mode == "r")
    return {
      read = function() return "test-jwt\n" end,
      close = function() end,
    }
  end
  return original_io_open(path, mode)
end

package.preload["cjson.safe"] = function()
  return {
    decode = function(body) return body end,
    encode = function(body) return body end,
  }
end
package.preload["resty.openssl.cipher"] = function() return {} end
package.preload["resty.openssl.rand"] = function() return {} end
package.preload["resty.openssl.pkey"] = function()
  return { new = function(der) return { der = der } end }
end
package.preload["resty.http"] = function()
  return {
    new = function()
      return {
        set_timeouts = function() end,
        connect = function() return true end,
        close = function() end,
        request = function(_, request)
          if request.method == "POST" then
            assert(request.path == "/v1/auth/kubernetes/login")
            assert(request.body.role == "encryptpii-kong" and request.body.jwt == "test-jwt")
            assert(request.headers["X-Vault-Token"] == nil,
              "Kubernetes login must not send a static Vault token")
            logins = logins + 1
            return {
              status = login_status,
              read_body = function()
                return { auth = { client_token = "login-token", lease_duration = 100 } }
              end,
            }
          end
          assert(request.headers["X-Vault-Token"] == "login-token",
            "Vault reads must use the Kubernetes login token")
          reads = reads + 1
          local body
          if request.path:find("/metadata/", 1, true) then
            body = { data = {
              current_version = current_version,
              versions = {
                ["1"] = { created_time = created_time, deletion_time = "", destroyed = false },
                ["2"] = { created_time = version2_created_time, deletion_time = "", destroyed = false },
              },
            } }
          else
            body = { data = { data = { privateKey = "test-key" } } }
          end
          return { status = 200, read_body = function() return body end }
        end,
      }
    end,
  }
end

ngx = {
  now = function() return now end,
  decode_base64 = function(value) return value end,
}
kong = { log = { err = function() end } }

local function upvalue(fn, name)
  for i = 1, math.huge do
    local key, value = debug.getupvalue(fn, i)
    assert(key, "Missing upvalue: " .. name)
    if key == name then
      return value
    end
  end
end

local plugin = dofile("/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/handler.lua")
assert(plugin.init_worker == nil, "Cache cleanup must not register a worker timer")
local decrypt_session_key = upvalue(plugin.access, "decrypt_session_key")
local get_private_key = upvalue(decrypt_session_key, "get_private_key")
local cache = upvalue(get_private_key, "key_cache")
local order = upvalue(get_private_key, "key_cache_order")
local config = {
  vault_addr = "http://vault:8200",
  vault_auth_role = "encryptpii-kong",
  vault_kubernetes_jwt_path = jwt_path,
  vault_secret_path = "secret/data/test",
  key_alias = "test",
  key_validity_millis = 10000,
  key_grace_period_millis = 5000,
}

local first = assert(get_private_key(config, "test:1"))
assert(#order == 1)
assert(cache[order[1]].expires_at == 1700000005,
  "An active key cache must not outlive the configured grace period")
assert(get_private_key(config, "test:1") == first)
assert(reads == 2, "Valid cache hits must avoid Vault")
assert(logins == 1, "The first Vault read must authenticate through Kubernetes")

now = 1700000005
assert(#order == 1, "Idle workers must leave cleanup until the next key access")
get_private_key(config, "invalid:1")
assert(#order == 0 and next(cache) == nil, "Key access must release expired key references")

now = 1700000000
created_time = os.date("!%Y-%m-%dT%H:%M:%SZ", now)
version2_created_time = created_time
config.key_validity_millis = 120000
config.key_grace_period_millis = 120000
assert(get_private_key(config, "test:1"))
assert(cache[order[1]].expires_at == now + 60, "Cache TTL must still be limited to 60 seconds")
now = now + 60
assert(get_private_key(config, "test:1"))
assert(#order == 1, "Reloading an expired key must not leave duplicate eviction entries")
assert(logins == 1, "Unexpired Kubernetes login tokens must be reused")

now = 1700000000
current_version = 2
config.key_validity_millis = 10000
config.key_grace_period_millis = 5000
assert(get_private_key(config, "test:1"))
assert(#order == 2, "Different expiry policies must not share a cached key")
now = 1700000015
local key, _, status, code = get_private_key(config, "test:1")
assert(not key and status == 400 and code == "stale_key")
assert(#order == 1, "Request-time cleanup must remove the expired key and its order entry")

now = 1700000000
current_version = 1
created_time = os.date("!%Y-%m-%dT%H:%M:%SZ", now)
version2_created_time = os.date("!%Y-%m-%dT%H:%M:%SZ", now + 15 * 24 * 60 * 60)
config.key_validity_millis = 30 * 24 * 60 * 60 * 1000
config.key_grace_period_millis = 24 * 60 * 60 * 1000
current_version = 2
now = now + 15 * 24 * 60 * 60 + 23 * 60 * 60
assert(get_private_key(config, "test:1"),
  "A rotated key must remain available during the full post-rotation grace period")
now = now + 60 * 60
local rotated_key, _, rotated_status, rotated_code = get_private_key(config, "test:1")
assert(not rotated_key and rotated_status == 400 and rotated_code == "stale_key",
  "A rotated key must expire exactly one grace period after the next version is created")

now = 1700000000
config.key_validity_millis = 120000
config.key_grace_period_millis = 120000
for i = 1, 20 do
  config.vault_secret_path = "secret/data/test-" .. i
  assert(get_private_key(config, "test:1"))
end
assert(#order == 16, "Cache size must stay bounded")
local seen = {}
for _, id in ipairs(order) do
  assert(cache[id] and not seen[id], "Eviction entries must be unique and reference a live cache entry")
  seen[id] = true
end
now = now + 60
get_private_key(config, "invalid:1")
assert(#order == 0 and next(cache) == nil, "Cleanup must clear both cache data structures")

local get_vault_token = upvalue(get_private_key, "get_vault_token")
local location = { host = "vault", port = 8200, scheme = "http", base_path = "" }
now = now + 30 * 24 * 60 * 60
assert(get_vault_token(config, location) == "login-token")
local previous_logins = logins
now = now + 80
assert(get_vault_token(config, location) == "login-token")
assert(logins == previous_logins + 1, "Expired login tokens must trigger Kubernetes login")
now = now + 80
login_status = 403
local rejected_token, login_err = get_vault_token(config, location)
assert(not rejected_token and login_err == "Vault is unavailable",
  "Failed Kubernetes login must not fall back to another authentication method")
config.vault_auth_role = nil
local missing_role_token, role_err = get_vault_token(config, location)
assert(not missing_role_token and role_err == "Vault is unavailable",
  "A Kubernetes role is required")
io.open = original_io_open

print("Private-key cache cleanup tests passed")
