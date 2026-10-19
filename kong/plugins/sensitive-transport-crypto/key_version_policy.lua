-- Key identifier and expiry policy helpers for the sensitive-transport-crypto plugin.

local MILLIS_PER_SECOND = 1000

local Policy = {}

function Policy.split_key_id(key_id)
  local alias, version
  if type(key_id) == "string" then
    alias = key_id:match("^([^:]*):") or key_id
    version = key_id:match("^[^:]+:([1-9]%d*)$")
    if version and (tonumber(version) > 2147483647 or tostring(tonumber(version)) ~= version) then
      version = nil
    end
  end
  return alias, version
end

function Policy.private_key_cache_expires_at(lookup_started_at, version, current_version, created_at, rotated_at,
  key_validity_millis, key_grace_period_millis)
  local cache_expires_at = lookup_started_at + 60
  local grace_deadline
  if tonumber(version) < current_version then
    grace_deadline = rotated_at + key_grace_period_millis
    if ngx.now() * MILLIS_PER_SECOND >= grace_deadline then
      return nil, "keyId refers to a key expired beyond its grace period", 400, "stale_key"
    end
    return math.min(cache_expires_at, grace_deadline / MILLIS_PER_SECOND)
  else
    -- Keep an active-key cache entry from outliving a full grace period after rotation.
    cache_expires_at = math.min(cache_expires_at, lookup_started_at + key_grace_period_millis / MILLIS_PER_SECOND)
  end
  -- With automatic rotation disabled, the SDK retains the active decryption key
  -- even beyond its advertised public-key validity and grace period.
  return cache_expires_at
end

function Policy.public_key_expires_at(created_at, key_validity_millis)
  return created_at + key_validity_millis
end

function Policy.public_key_refresh_at(expires_at, rotation_before_expiry_millis)
  return expires_at - rotation_before_expiry_millis
end

return Policy
