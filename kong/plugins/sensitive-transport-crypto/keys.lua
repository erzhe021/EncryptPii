-- This module provides functions to retrieve and cache private keys from a Vault server.

local pkey = require "resty.openssl.pkey"
local vault = require "kong.plugins.sensitive-transport-crypto.vault"

local KEY_CACHE_SIZE = 16
local KEY_CACHE_TTL_SECONDS = 60
local MILLIS_PER_SECOND = 1000
local STALE_KEY_ERROR = "stale_key"
local INVALID_KEY_ALIAS_ERROR = "invalid_key_alias"
local key_cache = {}
local key_cache_order = {}

local Keys = {}

local function remove_cached_key(cache_id)
    key_cache[cache_id] = nil
    for i = #key_cache_order, 1, -1 do
        if key_cache_order[i] == cache_id then
            table.remove(key_cache_order, i)
        end
    end
end

local function cleanup_key_cache()
    local now = ngx.now()
    for i = #key_cache_order, 1, -1 do
        local cache_id = key_cache_order[i]
        local cached = key_cache[cache_id]
        if not cached or cached.expires_at <= now then
            key_cache[cache_id] = nil
            table.remove(key_cache_order, i)
        end
    end
end

local function parse_vault_created_time(value)
    local year, month, day, hour, minute, second
    if type(value) == "string" then
        year, month, day, hour, minute, second = value:match("^(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)")
    end
    if not year or value:sub(-1) ~= "Z" then
        return nil
    end
    return os.time({
        year = tonumber(year),
        month = tonumber(month),
        day = tonumber(day),
        hour = tonumber(hour),
        min = tonumber(minute),
        sec = tonumber(second),
    }) * MILLIS_PER_SECOND
end

function Keys.get_private_key(config, key_id)
    cleanup_key_cache()
    local alias, version
    if type(key_id) == "string" then
        alias = key_id:match("^([^:]+)")
    end
    if alias ~= config.key_alias then
        return nil, "Invalid key alias", 400, INVALID_KEY_ALIAS_ERROR
    end
    if type(key_id) == "string" then
        version = key_id:match("^[^:]+:(%d+)$")
    end
    if not version then
        return nil, "keyId does not contain a valid version", 400, STALE_KEY_ERROR
    end

    local cache_id = config.vault_addr .. "|" .. config.vault_secret_path .. "|"
            .. config.key_validity_millis .. "|" .. config.key_grace_period_millis .. "|" .. key_id
    local cached = key_cache[cache_id]
    if cached and cached.expires_at > ngx.now() then
        return cached.key
    end

    local context, context_err = vault.get_context(config)
    if not context then
        return nil, context_err
    end

    local lookup_started_at = ngx.now()
    local cache_expires_at = lookup_started_at + KEY_CACHE_TTL_SECONDS
    local metadata_path = config.vault_secret_path:gsub("/data/", "/metadata/", 1)
    local metadata, metadata_err = vault.get_json(context, metadata_path)
    local metadata_data = metadata and metadata.data
    local current_version = metadata_data and tonumber(metadata_data.current_version)
    if not current_version then
        kong.log.err("Unable to read current key version from Vault: ", metadata_err or "missing metadata")
        return nil, "Vault key is unavailable"
    end

    if tonumber(version) > current_version then
        return nil, "keyId refers to a key version not present in Vault", 400, STALE_KEY_ERROR
    end
    local version_metadata = metadata_data.versions and metadata_data.versions[version]
    if not version_metadata or version_metadata.destroyed
            or (version_metadata.deletion_time and version_metadata.deletion_time ~= "") then
        return nil, "keyId refers to a key version not available in Vault", 400, STALE_KEY_ERROR
    end
    local created_at = parse_vault_created_time(version_metadata.created_time)
    if not created_at then
        kong.log.err("Unable to read Vault creation time for keyId ", key_id)
        return nil, "Vault key is unavailable"
    end
    local grace_deadline
    if tonumber(version) < current_version then
        local next_version_metadata = metadata_data.versions[tostring(tonumber(version) + 1)]
        local rotated_at = next_version_metadata
                and parse_vault_created_time(next_version_metadata.created_time)
        if not rotated_at then
            kong.log.err("Unable to read Vault rotation time for keyId ", key_id)
            return nil, "Vault key is unavailable"
        end
        grace_deadline = rotated_at + config.key_grace_period_millis
        if ngx.now() * MILLIS_PER_SECOND >= grace_deadline then
            return nil, "keyId refers to a key expired beyond its grace period", 400, STALE_KEY_ERROR
        end
    else
        grace_deadline = created_at
                + config.key_validity_millis
                + config.key_grace_period_millis
        -- Keep an active-key cache entry from outliving a full grace period after rotation.
        cache_expires_at = math.min(
                cache_expires_at,
                lookup_started_at + config.key_grace_period_millis / MILLIS_PER_SECOND
        )
    end
    cache_expires_at = math.min(cache_expires_at, grace_deadline / MILLIS_PER_SECOND)

    local secret_path = config.vault_secret_path .. "?version=" .. version
    local secret, secret_err = vault.get_json(context, secret_path)
    local private_key_base64 = secret
            and secret.data
            and secret.data.data
            and secret.data.data.privateKey
    if type(private_key_base64) ~= "string" or private_key_base64 == "" then
        kong.log.err("Vault response did not contain a private key for keyId ", key_id, ": ",
                secret_err or "missing field")
        return nil, "Vault key is unavailable"
    end

    local private_key_der = ngx.decode_base64(private_key_base64)
    if not private_key_der then
        kong.log.err("Vault private key is not valid base64 for keyId ", key_id)
        return nil, "Vault key is unavailable"
    end
    local key, key_err = pkey.new(private_key_der, { format = "DER", type = "pr" })
    if not key then
        kong.log.err("Unable to parse private key retrieved from Vault: ", key_err)
        return nil, "Vault key is unavailable"
    end

    -- Vault I/O yields; prune again before inserting in case another request filled the cache.
    cleanup_key_cache()
    remove_cached_key(cache_id)
    if cache_expires_at <= ngx.now() then
        return key
    end
    if #key_cache_order >= KEY_CACHE_SIZE then
        key_cache[table.remove(key_cache_order, 1)] = nil
    end
    key_cache[cache_id] = {
        key = key,
        expires_at = cache_expires_at,
    }
    key_cache_order[#key_cache_order + 1] = cache_id
    return key
end

function Keys.get_public_key_response(config)
    local context, context_err = vault.get_context(config)
    if not context then
        return nil, context_err
    end

    local metadata_path = config.vault_secret_path:gsub("/data/", "/metadata/", 1)
    local metadata, metadata_err = vault.get_json(context, metadata_path)
    local metadata_data = metadata and metadata.data
    local current_version = metadata_data and tonumber(metadata_data.current_version)
    if not current_version then
        kong.log.err("Unable to read current key version from Vault: ", metadata_err or "missing metadata")
        return nil, "Vault key is unavailable"
    end

    local version_metadata = metadata_data.versions
            and metadata_data.versions[tostring(current_version)]
    local created_at = version_metadata and parse_vault_created_time(version_metadata.created_time)
    if not created_at then
        kong.log.err("Unable to read Vault creation time for active key version ", current_version)
        return nil, "Vault key is unavailable"
    end

    local secret, secret_err = vault.get_json(
            context,
            config.vault_secret_path .. "?version=" .. current_version
    )
    local public_key_base64 = secret
            and secret.data
            and secret.data.data
            and secret.data.data.publicKey
    if type(public_key_base64) ~= "string" or public_key_base64 == ""
            or not ngx.decode_base64(public_key_base64) then
        kong.log.err("Vault response did not contain a valid public key for version ",
                current_version, ": ", secret_err or "missing or invalid publicKey")
        return nil, "Vault key is unavailable"
    end

    local expires_at = created_at + config.key_validity_millis
    if ngx.now() * MILLIS_PER_SECOND >= expires_at then
        kong.log.err("Active Vault key version ", current_version, " has expired")
        return nil, "Vault key is unavailable"
    end

    return {
        publicKeyBase64 = public_key_base64,
        keyId = config.key_alias .. ":" .. current_version,
        expiresAtEpochMillis = expires_at,
    }
end

return Keys
