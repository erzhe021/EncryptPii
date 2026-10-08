-- Request-phase orchestration for the sensitive-transport-crypto plugin.

local crypto = require "kong.plugins.sensitive-transport-crypto.crypto"
local errors = require "kong.plugins.sensitive-transport-crypto.errors"
local headers = require "kong.plugins.sensitive-transport-crypto.protocol"
local keys = require "kong.plugins.sensitive-transport-crypto.keys"
local size_limit = require "kong.plugins.sensitive-transport-crypto.size_limit"

local Access = {}

local function resolve_secret(value)
  if type(value) ~= "string" then
    return nil, "secret reference is missing"
  end
  if value:sub(1, 1) ~= "{" then
    return value
  end
  return kong.vault.get(value)
end

local function expired_or_invalid_key_response(key_error_code, config)
  if key_error_code == "stale_key" then
    return errors.expired_key_response(config)
  end
  if key_error_code == "invalid_key_alias" then
    return errors.invalid_key_response()
  end
  return nil
end

function Access.run(config)
  kong.ctx.plugin = kong.ctx.plugin or {}
  kong.ctx.plugin.encrypt_response = config.encrypt_response
  kong.ctx.plugin.plain_error_response = nil

  if config.serve_public_key then
    local public_key_response, public_key_err = keys.get_public_key_response(config)
    if not public_key_response then
      kong.log.err("Unable to serve the active Vault public key: ", public_key_err)
      return errors.json_error(503, "Public key is unavailable")
    end
    return kong.response.exit(200, public_key_response, {
      [headers.ENCRYPTED_RESPONSE_HEADER] = "false",
      ["Cache-Control"] = "no-store",
    })
  end

  local encrypted_request_body
  if config.decrypt_request then
    local body, err, status = size_limit.read_encrypted_request_body(config.max_body_bytes)
    if not body then
      return errors.json_error(status or 400, err)
    end
    encrypted_request_body = body
  end

  local session_key
  if config.decrypt_request or config.encrypt_response then
    local key_id = kong.request.get_header(headers.KEY_ID_HEADER)
    local encrypted_session_key = kong.request.get_header(headers.SESSION_KEY_HEADER)
    if type(key_id) ~= "string" or key_id == ""
      or type(encrypted_session_key) ~= "string" or encrypted_session_key == "" then
      return errors.json_error(400, "X-STC-Key-Id and X-STC-Session-Key are required; body key transport is unsupported")
    end
    local session_err, error_status, key_error_code
    session_key, session_err, error_status, key_error_code = crypto.decrypt_session_key(
      config, key_id, encrypted_session_key
    )
    if not session_key then
      kong.log.warn("Rejected request session key: ", session_err)
      local response = expired_or_invalid_key_response(key_error_code, config)
      if response then
        return response
      end
      return errors.json_error(error_status or 400, error_status and "Vault key is unavailable"
        or "Invalid request session key")
    end
    if config.encrypt_response then
      kong.ctx.plugin.session_key = session_key
    end
  end

  if config.decrypt_request then
    local plaintext, decrypt_err, decrypted_session_key, error_status, key_error_code =
      crypto.decrypt_request_body(encrypted_request_body, session_key)
    if not plaintext then
      kong.log.warn("Rejected encrypted request: ", decrypt_err)
      local response = expired_or_invalid_key_response(key_error_code, config)
      if response then
        return response
      end
      local message = "Invalid or undecryptable encrypted request"
      if decrypt_err == "session key fields are forbidden in the request body; use X-STC-Key-Id and X-STC-Session-Key"
        or decrypt_err == "request body may contain only ivBase64 and encryptedDataBase64" then
        message = decrypt_err
      end
      return errors.json_error(error_status or 400, error_status and "Request decryption is unavailable" or message)
    end

    kong.service.request.set_raw_body(plaintext)
    session_key = decrypted_session_key or session_key
  end

  kong.service.request.clear_header(headers.SESSION_KEY_HEADER)
  kong.service.request.clear_header(headers.KEY_ID_HEADER)
  local upstream_token, token_err = resolve_secret(config.upstream_auth_token)
  if not upstream_token or upstream_token == "" then
    kong.log.err("Unable to resolve the configured upstream authentication token: ", token_err)
    return errors.json_error(503, "Upstream authentication is unavailable")
  end

  kong.service.request.set_header(headers.GATEWAY_TOKEN_HEADER, upstream_token)
  kong.service.request.set_header("Accept-Encoding", "identity")
  kong.service.request.set_path(config.upstream_path)
  kong.ctx.plugin.max_body_bytes = config.max_body_bytes
end

return Access
