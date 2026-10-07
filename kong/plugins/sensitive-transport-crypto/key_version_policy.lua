-- Key identifier and expiry policy helpers for the sensitive-transport-crypto plugin.

local MILLIS_PER_SECOND = 1000

local Policy = {}

function Policy.split_key_id(key_id)
  local alias, version
  if type(key_id) == "string" then
    alias = key_id:match("^([^:]+)")
    version = key_id:match("^[^:]+:(%d+)$")
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
  else
    grace_deadline = created_at + key_validity_millis + key_grace_period_millis
    -- Keep an active-key cache entry from outliving a full grace period after rotation.
    cache_expires_at = math.min(cache_expires_at, lookup_started_at + key_grace_period_millis / MILLIS_PER_SECOND)
  end
  return math.min(cache_expires_at, grace_deadline / MILLIS_PER_SECOND)
end

function Policy.public_key_expires_at(created_at, key_validity_millis)
  return created_at + key_validity_millis
end

return Policy

