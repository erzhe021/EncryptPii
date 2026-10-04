-- This plugin is designed to provide end-to-end encryption for sensitive data in transit.

local crypto = require "kong.plugins.sensitive-transport-crypto.crypto"
local keys = require "kong.plugins.sensitive-transport-crypto.keys"

local KEY_ID_HEADER = "X-STC-KEY-ID"
local SESSION_KEY_HEADER = "X-STC-SESSION-KEY"
local GATEWAY_TOKEN_HEADER = "X-Crypto-Gateway-Token"
local KEY_EXPIRED_CODE = "KEY_EXPIRED"
local INVALID_KEY_CODE = "INVALID_KEY"
local CONTENT_TYPE_JSON = "application/json"

-- The plugin supports the following features:
-- 1. Request Decryption: Decrypts incoming requests that are encrypted using a session key. The session key is provided in the request body or headers, depending on the configuration.
-- 2. Response Encryption: Encrypts outgoing responses using the same session key, ensuring that sensitive data remains protected during transit.
-- 3. Public Key Serving: Provides an endpoint to serve the public key used for encrypting session keys, allowing clients to encrypt data before sending it to the server.
local CryptoKongPlugin = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}

local function json_error(status, message)
  return kong.response.exit(status, {
    message = message,
  })
end

local function json_key_error(status, code, message, data)
  return kong.response.exit(status, {
    code = code,
    msg = message,
    data = data,
  }, {
    ["Cache-Control"] = "no-store",
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

local function expired_key_response(config)
  local latest_key, latest_key_err = keys.get_public_key_response(config)
  if not latest_key then
    kong.log.err("Unable to include the latest public key in expired-key response: ", latest_key_err)
    return json_error(503, "Public key is unavailable")
  end
  return json_key_error(400, KEY_EXPIRED_CODE,
    "密钥版本已过期，请更新。新版本在data字段里。", latest_key)
end

function CryptoKongPlugin:access(config)
  if config.serve_public_key then
    local public_key_response, public_key_err = keys.get_public_key_response(config)
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
    local session_key, session_err, error_status, key_error_code = crypto.decrypt_session_key(
      config,
      kong.request.get_header(KEY_ID_HEADER),
      kong.request.get_header(SESSION_KEY_HEADER)
    )
    if not session_key then
      kong.log.warn("Rejected response-only session key: ", session_err)
      if key_error_code == "stale_key" then
        return expired_key_response(config)
      end
      if key_error_code == "invalid_key_alias" then
        return json_key_error(400, INVALID_KEY_CODE, "keyId中的keyAlias无效")
      end
      return json_error(error_status or 400, error_status and "Vault key is unavailable"
        or "Invalid response-only session key")
    end
    kong.ctx.plugin.session_key = session_key
  elseif config.decrypt_request then
    local content_length = tonumber(kong.request.get_header("Content-Length"))
    if content_length and content_length > config.max_body_bytes then
      kong.log.warn("Encrypted request Content-Length exceeds the crypto plugin size limit: bytes=",
        content_length, ", limit=", config.max_body_bytes)
      return json_error(413, "Request body exceeds the crypto plugin size limit")
    end

    local body, err = kong.request.get_raw_body()
    if not body then
      kong.log.warn("Unable to read encrypted request body: ", err)
      return json_error(400, "Encrypted request body is required")
    end
    if #body > config.max_body_bytes then
      kong.log.warn("Encrypted request body exceeds the crypto plugin size limit: bytes=",
        #body, ", limit=", config.max_body_bytes)
      return json_error(413, "Request body exceeds the crypto plugin size limit")
    end

    local plaintext, decrypt_err, session_key, error_status, key_error_code =
      crypto.decrypt_request_body(config, body)
    if not plaintext then
      kong.log.warn("Rejected encrypted request: ", decrypt_err)
      if key_error_code == "stale_key" then
        return expired_key_response(config)
      end
      if key_error_code == "invalid_key_alias" then
        return json_key_error(400, INVALID_KEY_CODE, "keyId中的keyAlias无效")
      end
      return json_error(error_status or 400, error_status and "Request decryption is unavailable"
        or "Invalid or undecryptable encrypted request")
    end

    kong.service.request.set_raw_body(plaintext)
    if config.encrypt_response then
      kong.ctx.plugin.session_key = session_key
    end
  end

  kong.service.request.clear_header(SESSION_KEY_HEADER)
  kong.service.request.clear_header(KEY_ID_HEADER)
  local upstream_token, token_err = resolve_secret(config.upstream_auth_token)
  if not upstream_token or upstream_token == "" then
    kong.log.err("Unable to resolve the configured upstream authentication token: ", token_err)
    return json_error(503, "Upstream authentication is unavailable")
  end

  kong.service.request.set_header(GATEWAY_TOKEN_HEADER, upstream_token)
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
  kong.response.set_header("Content-Type", CONTENT_TYPE_JSON)
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
      if not ctx.response_failed then
        kong.log.err("Upstream response exceeds the crypto plugin size limit: buffered bytes=",
          ctx.response_bytes, ", limit=", ctx.max_body_bytes)
      end
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
    ngx.header["Content-Type"] = CONTENT_TYPE_JSON
    ngx.arg[1] = '{"message":"Upstream response exceeds the crypto plugin size limit"}'
    ngx.arg[2] = true
    return
  end

  local plaintext = table.concat(ctx.response_chunks)
  ctx.response_chunks = nil
  if plaintext == "" then
    return
  end

  local response_body = crypto.encrypt_response(ctx.session_key, plaintext)
  if not response_body then
    ngx.status = 502
    ngx.arg[1] = '{"message":"Response encryption failed"}'
    ngx.arg[2] = true
    return
  end

  ngx.arg[1] = response_body
  ngx.arg[2] = true
end

return CryptoKongPlugin
