-- This module provides functions to retrieve and cache private keys from a Vault server.

local key_cache = require "kong.plugins.sensitive-transport-crypto.key_cache"
local key_parser = require "kong.plugins.sensitive-transport-crypto.key_parser"
local policy = require "kong.plugins.sensitive-transport-crypto.key_version_policy"
local vault = require "kong.plugins.sensitive-transport-crypto.vault"

local MILLIS_PER_SECOND = 1000
local STALE_KEY_ERROR = "stale_key"
local INVALID_KEY_ALIAS_ERROR = "invalid_key_alias"

local Keys = {}

function Keys.get_private_key(config, key_id)
    key_cache.cleanup()
    local alias, version = policy.split_key_id(key_id)
    if alias ~= config.key_alias then
        return nil, "Invalid key alias", 400, INVALID_KEY_ALIAS_ERROR
    end
    if not version then
        return nil, "keyId does not contain a valid version", 400, STALE_KEY_ERROR
    end

    local cache_id = config.vault_addr .. "|" .. config.vault_secret_path .. "|"
            .. config.key_validity_millis .. "|" .. config.key_grace_period_millis .. "|" .. key_id
    local cached = key_cache.get(cache_id)
    if cached then
        return cached
    end

    local context, context_err = vault.get_context(config)
    if not context then
        return nil, context_err
    end

    local lookup_started_at = ngx.now()
    local metadata_path = config.vault_secret_path:gsub("/data/", "/metadata/", 1)
    local metadata, metadata_err = vault.get_json(context, metadata_path)
    local metadata_data = metadata and metadata.data
    local current_version = metadata_data and tonumber(metadata_data.current_version)
    if not current_version then
        kong.log.err("Unable to read current key version from Vault: ", metadata_err or "missing metadata")
        return nil, "Vault key is unavailable"
    end

    local version_number = tonumber(version)
    if version_number > current_version then
        return nil, "keyId refers to a key version not present in Vault", 400, STALE_KEY_ERROR
    end
    local version_metadata = metadata_data.versions and metadata_data.versions[version]
    if not version_metadata or version_metadata.destroyed
            or (version_metadata.deletion_time and version_metadata.deletion_time ~= "") then
        return nil, "keyId refers to a key version not available in Vault", 400, STALE_KEY_ERROR
    end
    local created_at = key_parser.parse_vault_created_time(version_metadata.created_time)
    if not created_at then
        kong.log.err("Unable to read Vault creation time for keyId ", key_id)
        return nil, "Vault key is unavailable"
    end
    local cache_expires_at, cache_err, cache_status, cache_code
    if version_number < current_version then
        local next_version_metadata = metadata_data.versions[tostring(version_number + 1)]
        local rotated_at = next_version_metadata
                and key_parser.parse_vault_created_time(next_version_metadata.created_time)
        if not rotated_at then
            kong.log.err("Unable to read Vault rotation time for keyId ", key_id)
            return nil, "Vault key is unavailable"
        end
        cache_expires_at, cache_err, cache_status, cache_code = policy.private_key_cache_expires_at(
                lookup_started_at, version_number, current_version, created_at, rotated_at,
                config.key_validity_millis, config.key_grace_period_millis)
    else
        cache_expires_at, cache_err, cache_status, cache_code = policy.private_key_cache_expires_at(
                lookup_started_at, version_number, current_version, created_at, nil,
                config.key_validity_millis, config.key_grace_period_millis)
    end
    if not cache_expires_at then
        return nil, cache_err, cache_status, cache_code
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
