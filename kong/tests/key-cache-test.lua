local INITIAL_TIME_SECONDS = 1700000000
local SECONDS_PER_HOUR = 60 * 60
local SECONDS_PER_DAY = 24 * SECONDS_PER_HOUR
local MILLIS_PER_SECOND = 1000

local now = INITIAL_TIME_SECONDS
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

local plugin = dofile("/usr/local/share/lua/5.1/kong/plugins/sensitive-transport-crypto/handler.lua")
assert(plugin.init_worker == nil, "Cache cleanup must not register a worker timer")
local get_private_key = require("kong.plugins.sensitive-transport-crypto.keys").get_private_key
local get_vault_context = require("kong.plugins.sensitive-transport-crypto.vault").get_context
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
assert(get_private_key(config, "test:1") == first)
assert(reads == 2, "Valid cache hits must avoid Vault")
assert(logins == 1, "The first Vault read must authenticate through Kubernetes")

now = INITIAL_TIME_SECONDS + 5
get_private_key(config, "invalid:1")
assert(get_private_key(config, "test:1") ~= first,
  "Expired cached keys must be fetched again on the next valid access")
assert(reads == 4, "Expired-key cleanup must happen during a later key access")

now = INITIAL_TIME_SECONDS
created_time = os.date("!%Y-%m-%dT%H:%M:%SZ", now)
version2_created_time = created_time
config.key_validity_millis = 120000
config.key_grace_period_millis = 120000
local reads_before_policy_change = reads
assert(get_private_key(config, "test:1"))
assert(reads == reads_before_policy_change + 2,
  "Key cache entries must be isolated by validity and grace policies")
local reads_before_ttl = reads
now = now + 60
assert(get_private_key(config, "test:1"))
assert(reads == reads_before_ttl + 2, "Key cache TTL must remain limited to 60 seconds")
assert(logins == 1, "Unexpired Kubernetes login tokens must be reused")

now = INITIAL_TIME_SECONDS
current_version = 2
config.key_validity_millis = 10000
config.key_grace_period_millis = 5000
assert(get_private_key(config, "test:1"))
now = INITIAL_TIME_SECONDS + 15
local key, _, status, code = get_private_key(config, "test:1")
assert(not key and status == 400 and code == "stale_key")

now = INITIAL_TIME_SECONDS
current_version = 1
created_time = os.date("!%Y-%m-%dT%H:%M:%SZ", now)
version2_created_time = os.date("!%Y-%m-%dT%H:%M:%SZ", now + 15 * SECONDS_PER_DAY)
config.key_validity_millis = 30 * SECONDS_PER_DAY * MILLIS_PER_SECOND
config.key_grace_period_millis = SECONDS_PER_DAY * MILLIS_PER_SECOND
current_version = 2
now = now + 15 * SECONDS_PER_DAY + 23 * SECONDS_PER_HOUR
assert(get_private_key(config, "test:1"),
  "A rotated key must remain available during the full post-rotation grace period")
now = now + SECONDS_PER_HOUR
local rotated_key, _, rotated_status, rotated_code = get_private_key(config, "test:1")
assert(not rotated_key and rotated_status == 400 and rotated_code == "stale_key",
  "A rotated key must expire exactly one grace period after the next version is created")

now = INITIAL_TIME_SECONDS
config.key_validity_millis = 120000
config.key_grace_period_millis = 120000
for i = 1, 20 do
  config.vault_secret_path = "secret/data/test-" .. i
  assert(get_private_key(config, "test:1"))
end
local reads_before_eviction_check = reads
config.vault_secret_path = "secret/data/test-1"
assert(get_private_key(config, "test:1"))
assert(reads == reads_before_eviction_check + 2,
  "The cache must evict older entries when it reaches its 16-key limit")
reads_before_eviction_check = reads
config.vault_secret_path = "secret/data/test-20"
assert(get_private_key(config, "test:1"))
assert(reads == reads_before_eviction_check, "Recently used keys must remain cached")
now = now + 60
local reads_before_cleanup = reads
get_private_key(config, "invalid:1")
local refreshed_key, refresh_err = get_private_key(config, "test:1")
assert(refreshed_key, refresh_err)
assert(reads == reads_before_cleanup + 2, "Expired entries must be removed during later key access")

now = now + 30 * SECONDS_PER_DAY
assert(get_vault_context(config).token == "login-token")
local previous_logins = logins
now = now + 80
assert(get_vault_context(config).token == "login-token")
assert(logins == previous_logins + 1, "Expired login tokens must trigger Kubernetes login")
now = now + 80
login_status = 403
local rejected_context, login_err = get_vault_context(config)
assert(not rejected_context and login_err == "Vault is unavailable",
  "Failed Kubernetes login must not fall back to another authentication method")
config.vault_auth_role = nil
local missing_role_context, role_err = get_vault_context(config)
assert(not missing_role_context and role_err == "Vault is unavailable",
  "A Kubernetes role is required")
io.open = original_io_open

print("Private-key cache cleanup tests passed")
