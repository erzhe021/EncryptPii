local now = 1700000000
local metadata
local secrets = {}
local reads = {}
local context_error

ngx = {
  now = function() return now end,
  decode_base64 = function(value)
    if value ~= "invalid-base64" then
      return value
    end
  end,
}
kong = { log = { err = function() end } }
package.preload["resty.openssl.pkey"] = function()
  return { new = function(der)
    if der ~= "invalid-der" then
      return { der = der }
    end
    return nil, "invalid DER"
  end }
end
package.preload["kong.plugins.sensitive-transport-crypto.vault"] = function()
  return {
    get_context = function()
      if context_error then
        return nil, context_error
      end
      return {}
    end,
    get_json = function(_, path)
      reads[#reads + 1] = path
      if path:find("/metadata/", 1, true) then
        return { data = metadata }
      end
      local version = tonumber(path:match("%?version=(%d+)$"))
      local value = secrets[version]
      if not value then
        return nil, "not found"
      end
      return { data = { data = { privateKey = value, publicKey = value } } }
    end,
  }
end

local keys = require "kong.plugins.sensitive-transport-crypto.keys"
local parser = require "kong.plugins.sensitive-transport-crypto.key_parser"
local policy = require "kong.plugins.sensitive-transport-crypto.key_version_policy"
local config = {
  vault_addr = "http://vault",
  vault_secret_path = "secret/data/resolution",
  key_alias = "test",
  key_validity_millis = 10000,
  key_grace_period_millis = 5000,
  rotation_before_expiry_millis = 6000,
}
local function timestamp(seconds)
  return os.date("!%Y-%m-%dT%H:%M:%SZ", seconds)
end
local function reset(versions, current)
  config.vault_secret_path = config.vault_secret_path .. "-next"
  metadata = { current_version = current, versions = {} }
  secrets, reads = {}, {}
  for version, created in pairs(versions) do
    metadata.versions[tostring(version)] = { created_time = timestamp(created) }
    secrets[version] = "key-" .. version
  end
end
local function expect_candidates(key_id, expected, expected_code)
  local candidates, err, status, code = keys.get_private_key_candidates(config, key_id)
  assert(candidates, err)
  assert(#candidates == #expected, "wrong candidate count for " .. tostring(key_id))
  for i, version in ipairs(expected) do
    assert(candidates[i].der == "key-" .. version, "wrong candidate order")
  end
  assert(code == expected_code, "wrong deferred classification for " .. tostring(key_id))
  assert(not code or status == 400)
  return candidates
end

assert(parser.parse_vault_created_time("2023-11-14T22:13:20Z") == 1700000000000)
assert(parser.parse_vault_created_time("2023-11-14T22:13:20.123456789Z") == 1700000000123)
assert(parser.parse_vault_created_time("2024-02-29T00:00:00Z") == 1709164800000)
assert(not parser.parse_vault_created_time("2023-02-29T00:00:00Z"))
assert(not parser.parse_vault_created_time("2023-11-14T22:13:20junkZ"))
assert(not parser.parse_vault_created_time("2023-11-14T22:13:20.Z"))
assert(not parser.parse_vault_created_time("2023-11-14T22:13:20.1234567890Z"))
assert(not parser.parse_vault_created_time("2023-11-14T25:13:20Z"))

reset({ [1] = now - 100000 }, 1)
assert(not keys.get_cached_private_key(config, "test:1"), "Cold cache lookup must not access Vault")
assert(#reads == 0)
local cached_active = expect_candidates("test:1", { 1 })[1]
local cached_reads = #reads
context_error = "Vault is unavailable"
assert(keys.get_cached_private_key(config, "test:1") == cached_active,
  "A cached requested key remains available during a Vault outage")
assert(keys.get_private_key(config, "test:1") == cached_active)
for _, key_id in ipairs({ "other:1", "test", "test:01", "test:0", "", "test:2" }) do
  assert(not keys.get_cached_private_key(config, key_id), "Invalid or missing cache entry must return nil")
end
assert(not keys.get_cached_private_key(config, nil))
assert(#reads == cached_reads, "Cache-only lookup must never read Vault")
local original_path = config.vault_secret_path
config.vault_secret_path = original_path .. "-isolated"
assert(not keys.get_cached_private_key(config, "test:1"), "Cache lookup must isolate Vault paths")
config.vault_secret_path = original_path
config.key_grace_period_millis = 6000
assert(not keys.get_cached_private_key(config, "test:1"), "Cache lookup must isolate lifecycle policies")
config.key_grace_period_millis = 5000
now = now + 5
assert(not keys.get_cached_private_key(config, "test:1"), "Expired entries must not survive an outage")
assert(#reads == cached_reads)
context_error = nil
assert(keys.get_private_key(config, "test:1"), "Expired active key remains a decryption key")
assert(not keys.get_public_key_response(config), "Expired active key is not advertised to clients")

reset({ [1] = now - 100000, [2] = now - 2, [3] = now - 1 }, 3)
expect_candidates("test:2", { 2, 3, 1 })
expect_candidates("test:3", { 3, 2, 1 })
expect_candidates("test:03", { 3, 2, 1 })
expect_candidates("test:+3", { 3, 2, 1 })
expect_candidates("test:02", { 3, 2, 1 }, "stale_key")
expect_candidates(nil, { 3, 2, 1 })
expect_candidates("", { 3, 2, 1 })
expect_candidates("   ", { 3, 2, 1 })
expect_candidates("test:99", { 3, 2, 1 }, "stale_key")
expect_candidates("test", { 3, 2, 1 }, "stale_key")
expect_candidates("test:not-a-version", { 3, 2, 1 }, "stale_key")
expect_candidates("test:0", { 3, 2, 1 }, "stale_key")
expect_candidates("test:2:extra", { 3, 2, 1 }, "stale_key")
expect_candidates("test:2147483648", { 3, 2, 1 }, "stale_key")
local reads_before = #reads
local candidates, _, status, code = keys.get_private_key_candidates(config, "other:3")
assert(not candidates and status == 400 and code == "invalid_key_alias")
assert(#reads == reads_before, "Invalid aliases must not access Vault")
candidates, _, status, code = keys.get_private_key_candidates(config, ":3")
assert(not candidates and status == 400 and code == "invalid_key_alias")

now = now + 2
expect_candidates("test:1", { 1, 3, 2 })
now = now + 1
expect_candidates("test:1", { 3, 2 }, "stale_key")
now = now + 1
expect_candidates("test:2", { 3 }, "stale_key")

reset({ [1] = now - 100000, [2] = now - 100, [3] = now - 1 }, 3)
metadata.versions["2"].destroyed = true
expect_candidates("test:1", { 1, 3 })
metadata.versions["2"].destroyed = false
metadata.versions["2"].deletion_time = timestamp(now)
expect_candidates("test:2", { 3, 1 }, "stale_key")
now = now + 4
expect_candidates("test:1", { 3 }, "stale_key")

reset({ [1] = now - 1 }, 1)
local old = expect_candidates("test:1", { 1 })[1]
metadata.current_version = 2
metadata.versions["2"] = { created_time = timestamp(now) }
secrets[2] = "key-2"
expect_candidates("test:1", { 1, 2 })
now = now + 5
expect_candidates("test:1", { 2 }, "stale_key")
assert(old.der == "key-1", "Snapshots remain usable independently of later cache eviction")

reset({ [1] = now - 1, [2] = now }, 2)
secrets[1] = "invalid-der"
expect_candidates(nil, { 2 })
candidates, code = keys.get_private_key_candidates(config, "test:1")
assert(candidates and #candidates == 1 and candidates[1].der == "key-2" and code,
  "An unreadable requested key must not prevent trying the current key")
reset({ [1] = now - 1, [2] = now }, 2)
secrets[2] = "invalid-base64"
candidates, _, status = keys.get_private_key_candidates(config, "test:1")
assert(candidates and candidates[1].der == "key-1" and not status,
  "A bad fallback key must not prevent trying an available requested key")

reset({ [1] = now }, 1)
context_error = "Vault is unavailable"
candidates, code = keys.get_private_key_candidates(config, "test:1")
assert(not candidates and code == context_error)
context_error = nil
metadata.current_version = nil
assert(not keys.get_private_key_candidates(config, "test:1"))

local expires = policy.private_key_cache_expires_at(now, 1, 1, 0, nil, 1, 0)
assert(expires == now, "Zero grace must disable active-key caching without rejecting the key")
print("Key resolution and lifecycle tests passed")
