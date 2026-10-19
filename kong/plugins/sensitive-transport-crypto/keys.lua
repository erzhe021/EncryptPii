-- This module provides functions to retrieve and cache private keys from a Vault server.

local key_cache = require "kong.plugins.sensitive-transport-crypto.key_cache"
local key_parser = require "kong.plugins.sensitive-transport-crypto.key_parser"
local policy = require "kong.plugins.sensitive-transport-crypto.key_version_policy"
local vault = require "kong.plugins.sensitive-transport-crypto.vault"

local MILLIS_PER_SECOND = 1000
local STALE_KEY_ERROR = "stale_key"
local INVALID_KEY_ALIAS_ERROR = "invalid_key_alias"

local Keys = {}

local function cache_id_for(config, key_id)
    return config.vault_addr .. "|" .. config.vault_secret_path .. "|"
            .. config.key_validity_millis .. "|" .. config.key_grace_period_millis .. "|" .. key_id
end

local function read_metadata(config)
    local context, context_err = vault.get_context(config)
    if not context then
        return nil, context_err
    end
    local metadata_path = config.vault_secret_path:gsub("/data/", "/metadata/", 1)
    local metadata, metadata_err = vault.get_json(context, metadata_path)
    local metadata_data = metadata and metadata.data
    local current_version = metadata_data and tonumber(metadata_data.current_version)
    if not current_version or current_version < 1 or current_version % 1 ~= 0 then
        kong.log.err("Unable to read current key version from Vault: ", metadata_err or "missing metadata")
        return nil, "Vault key is unavailable"
    end
    return metadata_data, context, current_version
end

local function available(metadata)
    return metadata and not metadata.destroyed
        and (not metadata.deletion_time or metadata.deletion_time == "")
end

local function read_private_key(config, context, version, cache_expires_at)
    local key_id = config.key_alias .. ":" .. version
    local cache_id = cache_id_for(config, key_id)
    local cached = key_cache.get(cache_id)
    if cached then
        return cached
    end
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

    -- Vault I/O yields; prune again before inserting in case another request filled the cache.
    key_cache.cleanup()
    local key, key_err = key_parser.parse_private_key(private_key_base64, key_id)
    if not key then
        return nil, key_err
    end
    if cache_expires_at <= ngx.now() then
        return key
    end
    key_cache.put(cache_id, key, cache_expires_at)
    return key
end

local function version_expiry(config, metadata, version, current_version, lookup_started_at)
    local entry = metadata.versions and metadata.versions[tostring(version)]
    if version > current_version or not available(entry) then
        return nil, "keyId refers to a key version not available in Vault", 400, STALE_KEY_ERROR
    end
    local created_at = key_parser.parse_vault_created_time(entry.created_time)
    if not created_at then
        return nil, "Vault key is unavailable"
    end
    local rotated_at
    if version < current_version then
        local next_version
        for id, next_entry in pairs(metadata.versions or {}) do
            local number = tonumber(id)
            if number and number > version and number <= current_version and available(next_entry)
                    and (not next_version or number < next_version) then
                next_version = number
                rotated_at = key_parser.parse_vault_created_time(next_entry.created_time)
            end
        end
        if not rotated_at then
            return nil, "Vault key is unavailable"
        end
    end
    return policy.private_key_cache_expires_at(lookup_started_at, version, current_version, created_at,
        rotated_at, config.key_validity_millis, config.key_grace_period_millis)
end

function Keys.get_cached_private_key(config, key_id)
    key_cache.cleanup()
    local alias, version = policy.split_key_id(key_id)
    if alias ~= config.key_alias or not version then
        return nil
    end
    return key_cache.get(cache_id_for(config, key_id))
end

function Keys.get_private_key(config, key_id)
    key_cache.cleanup()
    local alias, version = policy.split_key_id(key_id)
    if alias ~= config.key_alias then
        return nil, "Invalid key alias", 400, INVALID_KEY_ALIAS_ERROR
    end
    if not version then
        return nil, "keyId does not contain a valid version", 400, STALE_KEY_ERROR
    end
    local cached = Keys.get_cached_private_key(config, key_id)
    if cached then
        return cached
    end
    local lookup_started_at = ngx.now()
    local metadata, context, current_version = read_metadata(config)
    if not metadata then
        return nil, context
    end
    local expires_at, err, status, code = version_expiry(
        config, metadata, tonumber(version), current_version, lookup_started_at)
    if not expires_at then
        return nil, err, status, code
    end
    return read_private_key(config, context, version, expires_at)
end

-- Error classification accompanying a non-nil candidate list is deferred until
-- every candidate fails RSA decryption; an outdated hint must not reject valid ciphertext.
function Keys.get_private_key_candidates(config, key_id)
    key_cache.cleanup()
    local has_key_id = type(key_id) == "string" and key_id:find("%S") ~= nil
    local alias, requested_version = policy.split_key_id(key_id)
    if has_key_id and alias ~= config.key_alias then
        return nil, "Invalid key alias", 400, INVALID_KEY_ALIAS_ERROR
    end
    local lookup_started_at = ngx.now()
    local metadata, context, current_version = read_metadata(config)
    if not metadata then
        return nil, context
    end
    local versions = {}
    for id in pairs(metadata.versions or {}) do
        local number = tonumber(id)
        if number and number >= 1 and number < current_version and number % 1 == 0 then
            versions[#versions + 1] = number
        end
    end
    table.sort(versions, function(a, b) return a > b end)
    local ordered = {}
    if requested_version then
        ordered[#ordered + 1] = tonumber(requested_version)
    end
    ordered[#ordered + 1] = current_version
    for _, version in ipairs(versions) do
        ordered[#ordered + 1] = version
    end
    local candidates, seen = {}, {}
    local requested_available = false
    local resolution_err
    for _, version in ipairs(ordered) do
        if not seen[version] then
            seen[version] = true
            local expires_at, err, _, code = version_expiry(
                config, metadata, version, current_version, lookup_started_at)
            if expires_at then
                local key, key_err = read_private_key(config, context, tostring(version), expires_at)
                if key then
                    candidates[#candidates + 1] = key
                    if requested_version and version == tonumber(requested_version) then
                        requested_available = true
                    end
                elseif version == current_version or (requested_version and version == tonumber(requested_version)) then
                    resolution_err = key_err
                end
            elseif version == current_version or (not code and requested_version
                    and version == tonumber(requested_version)) then
                resolution_err = code and "Vault key is unavailable" or err
            end
        end
    end
    if resolution_err then
        if #candidates == 0 then
            return nil, resolution_err
        end
        return candidates, resolution_err
    end
    if has_key_id and not requested_available then
        local numeric_hint = key_id:match("^[^:]+:([+-]?%d+)$")
        if numeric_hint and tonumber(numeric_hint) == current_version then
            return candidates
        end
        return candidates, "keyId refers to a key version not available in Vault", 400, STALE_KEY_ERROR
    end
    return candidates
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
    local created_at = version_metadata and key_parser.parse_vault_created_time(version_metadata.created_time)
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

    local expires_at = policy.public_key_expires_at(created_at, config.key_validity_millis)
    if ngx.now() * MILLIS_PER_SECOND >= expires_at then
        kong.log.err("Active Vault key version ", current_version, " has expired")
        return nil, "Vault key is unavailable"
    end
    if config.key_grace_period_millis >= config.rotation_before_expiry_millis
            or config.rotation_before_expiry_millis >= config.key_validity_millis then
        kong.log.err("Key lifecycle settings must satisfy grace period < rotation-before-expiry < validity")
        return nil, "Vault key is unavailable"
    end

    return {
        publicKeyBase64 = public_key_base64,
        keyId = config.key_alias .. ":" .. current_version,
        expiresAtEpochMillis = expires_at,
        refreshAtEpochMillis = policy.public_key_refresh_at(
                expires_at, config.rotation_before_expiry_millis),
    }
end

return Keys
