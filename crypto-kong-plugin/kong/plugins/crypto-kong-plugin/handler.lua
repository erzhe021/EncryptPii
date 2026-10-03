local cjson = require "cjson.safe"
local cipher = require "resty.openssl.cipher"
local http = require "resty.http"
local pkey = require "resty.openssl.pkey"
local random = require "resty.openssl.rand"

local KEY_CACHE_SIZE = 16
local KEY_CACHE_TTL_SECONDS = 60
local GCM_IV_BYTES = 12
local GCM_TAG_BYTES = 16
local AES_KEY_BYTES = 32
local OAEP_OPTIONS = {
  oaep_md = "sha256",
  -- The Java SDK uses the JCA default MGF1 digest for this transformation.
  mgf1_md = "sha1",
}
local key_cache = {}
local key_cache_order = {}

local CryptoKongPlugin = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}

local function json_error(status, message)
  return kong.response.exit(status, {
    message = message,
  })
end

local function resolve_secret(value)
  if type(value) ~= "string" then
    return nil, "secret reference is missing"
  end
  if value:sub(1, 1) ~= "{" then
    return value
  end
  return kong.vault.get(value)
end

local function parse_vault_location(vault_addr)
  local scheme, authority_and_path = vault_addr:match("^(https?)://(.+)$")
  local authority, base_path
  if authority_and_path then
    authority, base_path = authority_and_path:match("^([^/]+)(/.*)$")
    authority = authority or authority_and_path
  end
  local host, port
  if authority then
    host, port = authority:match("^([^:]+):?(%d*)$")
  end
  if not scheme or not host then
    return nil, "Invalid configured Vault address"
  end
  return {
    scheme = scheme,
    host = host,
    port = tonumber(port) or (scheme == "https" and 443 or 80),
    base_path = base_path and base_path ~= "/" and base_path or "",
  }
end

local function get_vault_json(config, token, location, path)
  local httpc = http.new()
  httpc:set_timeouts(1000, 1000, 2000)
  local ok, connect_err = httpc:connect({
    scheme = location.scheme,
    host = location.host,
    port = location.port,
    ssl_verify = location.scheme == "https",
  })
  if not ok then
    kong.log.err("Unable to connect to Vault: ", connect_err)
    return nil, "Vault is unavailable"
  end

  local response, request_err = httpc:request({
    method = "GET",
    path = location.base_path .. "/v1/" .. path,
    headers = {
      ["X-Vault-Token"] = token,
      ["Accept"] = "application/json",
    },
  })
  if not response then
    kong.log.err("Vault request failed: ", request_err)
    httpc:close()
    return nil, "Vault is unavailable"
  end

  local response_body, body_err = response:read_body()
  httpc:close()
  if response.status ~= 200 or not response_body then
    kong.log.err("Vault request returned HTTP ", response.status, ": ", body_err or "no response body")
    return nil, "Vault key is unavailable"
  end

  local decoded, decode_err = cjson.decode(response_body)
  if not decoded then
    kong.log.err("Vault returned invalid JSON: ", decode_err)
    return nil, "Vault key is unavailable"
  end
  return decoded
end

local function parse_vault_created_time(value)
  local year, month, day, hour, minute, second
  if type(value) == "string" then
    year, month, day, hour, minute, second =
      value:match("^(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)")
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
  }) * 1000
end

local function get_private_key(config, key_id)
  local cached = key_cache[key_id]
  if cached and cached.expires_at > ngx.now() then
    return cached.key
  end

  local alias, version
  if type(key_id) == "string" then
    alias, version = key_id:match("^([^:]+):(%d+)$")
  end
  if alias ~= config.key_alias then
    return nil, "keyId does not match the configured key alias", 400
  end

  local location, location_err = parse_vault_location(config.vault_addr)
  if not location then
    kong.log.err(location_err)
    return nil, "Vault is unavailable"
  end

  local vault_token, token_err = resolve_secret(config.vault_token)
  if not vault_token or vault_token == "" then
    kong.log.err("Unable to resolve the configured Vault token: ", token_err)
    return nil, "Vault is unavailable"
  end

  local cache_expires_at = ngx.now() + KEY_CACHE_TTL_SECONDS
  local metadata_path = config.vault_secret_path:gsub("/data/", "/metadata/", 1)
  local metadata, metadata_err = get_vault_json(config, vault_token, location, metadata_path)
  local metadata_data = metadata and metadata.data
  local current_version = metadata_data and tonumber(metadata_data.current_version)
  if not current_version then
    kong.log.err("Unable to read current key version from Vault: ", metadata_err or "missing metadata")
    return nil, "Vault key is unavailable"
  end

  if tonumber(version) > current_version then
    return nil, "keyId refers to a key version not present in Vault", 400
  end
  if tonumber(version) < current_version then
    local version_metadata = metadata_data.versions and metadata_data.versions[version]
    local created_at = version_metadata and parse_vault_created_time(version_metadata.created_time)
    if not created_at then
      kong.log.err("Unable to read Vault creation time for historical keyId ", key_id)
      return nil, "Vault key is unavailable"
    end
    local grace_deadline = created_at
      + config.key_validity_millis
      + config.key_grace_period_millis
    if ngx.now() * 1000 >= grace_deadline then
      return nil, "keyId refers to a key expired beyond its grace period", 400
    end
    cache_expires_at = math.min(cache_expires_at, grace_deadline / 1000)
  end

  local secret_path = config.vault_secret_path .. "?version=" .. version
  local secret, secret_err = get_vault_json(config, vault_token, location, secret_path)
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

  if #key_cache_order == KEY_CACHE_SIZE then
    key_cache[table.remove(key_cache_order, 1)] = nil
  end
  key_cache[key_id] = {
    key = key,
    expires_at = cache_expires_at,
  }
  key_cache_order[#key_cache_order + 1] = key_id
  return key
end

local function get_public_key_response(config)
  local location, location_err = parse_vault_location(config.vault_addr)
  if not location then
    kong.log.err(location_err)
    return nil, "Vault is unavailable"
  end

  local vault_token, token_err = resolve_secret(config.vault_token)
  if not vault_token or vault_token == "" then
    kong.log.err("Unable to resolve the configured Vault token: ", token_err)
    return nil, "Vault is unavailable"
  end

  local metadata_path = config.vault_secret_path:gsub("/data/", "/metadata/", 1)
  local metadata, metadata_err = get_vault_json(config, vault_token, location, metadata_path)
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

  local secret, secret_err = get_vault_json(
    config,
    vault_token,
    location,
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
  if ngx.now() * 1000 >= expires_at then
    kong.log.err("Active Vault key version ", current_version, " has expired")
    return nil, "Vault key is unavailable"
  end

  return {
    publicKeyBase64 = public_key_base64,
    keyId = config.key_alias .. ":" .. current_version,
    expiresAtEpochMillis = expires_at,
  }
end

local function decode_base64(value, field_name)
  if type(value) ~= "string" or value == "" then
    return nil, field_name .. " is required"
  end

  local decoded = ngx.decode_base64(value)
  if not decoded then
    return nil, field_name .. " must be valid base64"
  end

  return decoded
end

local function decrypt_session_key(config, key_id, encrypted_session_key_base64)
  if type(key_id) ~= "string" or key_id == "" then
    return nil, "keyId is required"
  end

  local encrypted_session_key, decode_err =
    decode_base64(encrypted_session_key_base64, "encrypted session key")
  if not encrypted_session_key then
    return nil, decode_err
  end

  local private_key, key_err, key_status = get_private_key(config, key_id)
  if not private_key then
    return nil, key_err, key_status or 503
  end

  local session_key, rsa_err = private_key:decrypt(
    encrypted_session_key,
    pkey.PADDINGS.RSA_PKCS1_OAEP_PADDING,
    OAEP_OPTIONS
  )
  if not session_key then
    kong.log.warn("Failed to decrypt request session key: ", rsa_err)
    return nil, "request session key could not be decrypted"
  end
  if #session_key ~= AES_KEY_BYTES then
    return nil, "decrypted session key must be 32 bytes"
  end
  return session_key
end

local function decrypt_request_body(config, body)
  local payload, err = cjson.decode(body)
  if not payload or type(payload) ~= "table" then
    return nil, err or "request body must be a JSON object"
  end

  local iv, iv_err = decode_base64(payload.ivBase64, "ivBase64")
  if not iv then
    return nil, iv_err
  end
  if #iv ~= GCM_IV_BYTES then
    return nil, "ivBase64 must decode to a 12-byte IV"
  end

  local encrypted_data, data_err =
    decode_base64(payload.encryptedDataBase64, "encryptedDataBase64")
  if not encrypted_data then
    return nil, data_err
  end
  if #encrypted_data < GCM_TAG_BYTES then
    return nil, "encryptedDataBase64 is too short"
  end

  local session_key, rsa_err, key_status =
    decrypt_session_key(config, payload.keyId, payload.encryptedSessionKeyBase64)
  if not session_key then
    return nil, rsa_err, nil, key_status
  end

  local ciphertext = encrypted_data:sub(1, -GCM_TAG_BYTES - 1)
  local tag = encrypted_data:sub(-GCM_TAG_BYTES)
  local aes, aes_err = cipher.new("aes-256-gcm")
  if not aes then
    kong.log.err("Unable to initialize AES-GCM: ", aes_err)
    return nil, "request decryption is unavailable", nil, 500
  end

  local plaintext, decrypt_err = aes:decrypt(session_key, iv, ciphertext, false, nil, tag)
  if not plaintext then
    kong.log.warn("Failed to authenticate or decrypt request payload: ", decrypt_err)
    return nil, "request payload authentication failed"
  end

  return plaintext, nil, session_key
end

function CryptoKongPlugin:access(config)
  if config.serve_public_key then
    local public_key_response, public_key_err = get_public_key_response(config)
    if not public_key_response then
      kong.log.err("Unable to serve the active Vault public key: ", public_key_err)
      return json_error(503, "Public key is unavailable")
    end
    return kong.response.exit(200, public_key_response, {
      ["Cache-Control"] = "no-store",
    })
  end

  if config.decrypt_request and config.session_key_source ~= "body" then
    kong.log.err("request decryption requires body session-key transport")
    return json_error(500, "Invalid crypto plugin configuration")
  end
  if config.session_key_source == "header" and not config.encrypt_response then
    kong.log.err("header session-key transport is only supported for response encryption")
    return json_error(500, "Invalid crypto plugin configuration")
  end
  if config.encrypt_response and not config.decrypt_request and config.session_key_source ~= "header" then
    kong.log.err("response encryption without request decryption requires header session-key transport")
    return json_error(500, "Invalid crypto plugin configuration")
  end

  if config.session_key_source == "header" then
    local session_key, session_err, error_status = decrypt_session_key(
      config,
      kong.request.get_header("X-STC-KEY-ID"),
      kong.request.get_header("X-STC-SESSION-KEY")
    )
    if not session_key then
      kong.log.warn("Rejected response-only session key: ", session_err)
      return json_error(error_status or 400, error_status and "Vault key is unavailable"
        or "Invalid response-only session key")
    end
    kong.ctx.plugin.session_key = session_key
  elseif config.decrypt_request then
    local content_length = tonumber(kong.request.get_header("Content-Length"))
    if content_length and content_length > config.max_body_bytes then
      return json_error(413, "Request body exceeds the crypto plugin size limit")
    end

    local body, err = kong.request.get_raw_body()
    if not body then
      kong.log.warn("Unable to read encrypted request body: ", err)
      return json_error(400, "Encrypted request body is required")
    end
    if #body > config.max_body_bytes then
      return json_error(413, "Request body exceeds the crypto plugin size limit")
    end

    local plaintext, decrypt_err, session_key, error_status = decrypt_request_body(config, body)
    if not plaintext then
      kong.log.warn("Rejected encrypted request: ", decrypt_err)
      return json_error(error_status or 400, error_status and "Request decryption is unavailable"
        or "Invalid or undecryptable encrypted request")
    end

    kong.service.request.set_raw_body(plaintext)
    if config.encrypt_response then
      kong.ctx.plugin.session_key = session_key
    end
  end

  kong.service.request.clear_header("X-STC-SESSION-KEY")
  kong.service.request.clear_header("X-STC-KEY-ID")
  local upstream_token, token_err = resolve_secret(config.upstream_auth_token)
  if not upstream_token or upstream_token == "" then
    kong.log.err("Unable to resolve the configured upstream authentication token: ", token_err)
    return json_error(503, "Upstream authentication is unavailable")
  end

  kong.service.request.set_header("X-Crypto-Gateway-Token", upstream_token)
  kong.service.request.set_header("Accept-Encoding", "identity")
  kong.service.request.set_path(config.upstream_path)
  kong.ctx.plugin.max_body_bytes = config.max_body_bytes
end

function CryptoKongPlugin:header_filter()
  if not kong.ctx.plugin.session_key then
    return
  end

  kong.response.clear_header("Content-Length")
  kong.response.clear_header("Content-Encoding")
  kong.response.clear_header("ETag")
  kong.response.clear_header("Content-MD5")
  kong.response.set_header("Content-Type", "application/json")
  kong.ctx.plugin.response_chunks = {}
  kong.ctx.plugin.response_bytes = 0
end

function CryptoKongPlugin:body_filter()
  local ctx = kong.ctx.plugin
  if not ctx.session_key then
    return
  end

  local chunk = ngx.arg[1]
  local eof = ngx.arg[2]
  if chunk and #chunk > 0 then
    ctx.response_bytes = ctx.response_bytes + #chunk
    if ctx.response_bytes > ctx.max_body_bytes then
      ctx.response_chunks = nil
      ctx.response_failed = true
    elseif not ctx.response_failed then
      ctx.response_chunks[#ctx.response_chunks + 1] = chunk
    end
  end

  ngx.arg[1] = ""
  if not eof then
    return
  end

  if ctx.response_failed then
    ngx.status = 502
    ngx.header["Content-Type"] = "application/json"
    ngx.arg[1] = '{"message":"Upstream response exceeds the crypto plugin size limit"}'
    ngx.arg[2] = true
    return
  end

  local plaintext = table.concat(ctx.response_chunks)
  ctx.response_chunks = nil
  if plaintext == "" then
    return
  end

  local iv, random_err = random.bytes(GCM_IV_BYTES, true)
  if not iv then
    kong.log.err("Unable to generate response IV: ", random_err)
    ngx.status = 502
    ngx.arg[1] = '{"message":"Response encryption failed"}'
    ngx.arg[2] = true
    return
  end

  local aes, cipher_err = cipher.new("aes-256-gcm")
  if not aes then
    kong.log.err("Unable to initialize response AES-GCM: ", cipher_err)
    ngx.status = 502
    ngx.arg[1] = '{"message":"Response encryption failed"}'
    ngx.arg[2] = true
    return
  end

  local ciphertext, encrypt_err = aes:encrypt(ctx.session_key, iv, plaintext)
  if not ciphertext then
    kong.log.err("Unable to encrypt upstream response: ", encrypt_err)
    ngx.status = 502
    ngx.arg[1] = '{"message":"Response encryption failed"}'
    ngx.arg[2] = true
    return
  end

  local tag, tag_err = aes:get_aead_tag(GCM_TAG_BYTES)
  if not tag then
    kong.log.err("Unable to obtain response AES-GCM tag: ", tag_err)
    ngx.status = 502
    ngx.arg[1] = '{"message":"Response encryption failed"}'
    ngx.arg[2] = true
    return
  end

  local response_body, encode_err = cjson.encode({
    ivBase64 = ngx.encode_base64(iv),
    encryptedDataBase64 = ngx.encode_base64(ciphertext .. tag),
  })
  if not response_body then
    kong.log.err("Unable to encode encrypted response: ", encode_err)
    ngx.status = 502
    ngx.arg[1] = '{"message":"Response encryption failed"}'
    ngx.arg[2] = true
    return
  end

  ngx.arg[1] = response_body
  ngx.arg[2] = true
end

return CryptoKongPlugin
