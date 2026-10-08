-- In-memory cache for Vault-backed private keys.

local KEY_CACHE_SIZE = 16
local KEY_CACHE_TTL_SECONDS = 60

local cache = {}
local order = {}

local KeyCache = {}

function KeyCache.cleanup(now)
  now = now or ngx.now()
  for i = #order, 1, -1 do
    local cache_id = order[i]
    local cached = cache[cache_id]
    if not cached or cached.expires_at <= now then
      cache[cache_id] = nil
      table.remove(order, i)
    end
  end
end

function KeyCache.get(cache_id, now)
  now = now or ngx.now()
  local cached = cache[cache_id]
  if cached and cached.expires_at > now then
    return cached.key
  end
  return nil
end

function KeyCache.put(cache_id, key, expires_at, now)
  now = now or ngx.now()
  KeyCache.cleanup(now)
  cache[cache_id] = nil
  for i = #order, 1, -1 do
    if order[i] == cache_id then
      table.remove(order, i)
    end
  end
  if expires_at <= now then
    return key
  end
  if #order >= KEY_CACHE_SIZE then
    cache[table.remove(order, 1)] = nil
  end
  cache[cache_id] = {
    key = key,
    expires_at = expires_at,
  }
  order[#order + 1] = cache_id
  return key
end

function KeyCache.ttl_seconds()
  return KEY_CACHE_TTL_SECONDS
end

return KeyCache

