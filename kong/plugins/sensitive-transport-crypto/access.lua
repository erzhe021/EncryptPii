-- Request-phase orchestration for the sensitive-transport-crypto plugin.

local crypto = require "kong.plugins.sensitive-transport-crypto.crypto"
local errors = require "kong.plugins.sensitive-transport-crypto.errors"
local headers = require "kong.plugins.sensitive-transport-crypto.protocol"
local keys = require "kong.plugins.sensitive-transport-crypto.keys"
local size_limit = require "kong.plugins.sensitive-transport-crypto.size_limit"
local payload_codec = require "kong.plugins.sensitive-transport-crypto.payload"

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

local function read_single_header(request_headers, name)
  local value = request_headers[name:lower()]
  if value == nil then
    return nil
  end
  if type(value) ~= "string" then
    return nil, name .. " must not be repeated"
  end
  return value
end

function Access.run(config)
  kong.ctx.plugin = kong.ctx.plugin or {}
  kong.ctx.plugin.encrypt_response = false
  kong.ctx.plugin.session_key = nil
  kong.ctx.plugin.plain_error_response = nil
  kong.ctx.plugin.response_failed = nil

  local request_headers, headers_err = kong.request.get_headers(1000)
  if headers_err then
    return errors.json_error(400, "Unable to read complete request headers.")
  end
  local enabled_header, enabled_header_err = read_single_header(request_headers, headers.ENABLED_HEADER)
  local key_id, key_id_err = read_single_header(request_headers, headers.KEY_ID_HEADER)
  local encrypted_session_key, session_key_header_err = read_single_header(request_headers, headers.SESSION_KEY_HEADER)
  if enabled_header_err or key_id_err or session_key_header_err then
    return errors.json_error(400, enabled_header_err or key_id_err or session_key_header_err)
  end

  local enabled = false
  if enabled_header ~= nil then
    if enabled_header:lower() == "true" then
      enabled = true
    elseif enabled_header:lower() ~= "false" then
      return errors.json_error(400, "X-STC-Enabled must be a single true or false value.")
    end
  end

  local has_key_id = key_id ~= nil
  local has_session_key = encrypted_session_key ~= nil
  if not enabled and (has_key_id or has_session_key) then
    return errors.json_error(400, "X-STC-Key-Id and X-STC-Session-Key are only valid together with X-STC-Enabled: true")
  end

  if config.serve_public_key then
    if enabled then
      return errors.json_error(400, "Endpoint does not support transport crypto.")
    end
    if not config.crypto_enabled then
      return errors.json_error(404, "Public key endpoint is disabled")
    end
    local public_key_response, public_key_err = keys.get_public_key_response(config)
    if not public_key_response then
      kong.log.err("Unable to serve the active Vault public key: ", public_key_err)
      return errors.json_error(500, "Public key is unavailable")
    end
    return kong.response.exit(200, public_key_response, {
      [headers.ENCRYPTED_RESPONSE_HEADER] = "false",
      ["Cache-Control"] = "no-store",
    })
  end

  if enabled and not config.crypto_enabled then
    return errors.json_error(400, "Server transport crypto is disabled.")
  end
  if enabled and not config.decrypt_request and not config.encrypt_response then
    return errors.json_error(400, "X-STC-Enabled: true requires request decryption or response encryption on this route")
  end

  local decrypt_request = enabled and config.decrypt_request
  local encrypt_response = enabled and config.encrypt_response
  kong.ctx.plugin.encrypt_response = encrypt_response

  if decrypt_request or encrypt_response then
    if type(key_id) ~= "string" or not key_id:find("%S")
      or type(encrypted_session_key) ~= "string" or not encrypted_session_key:find("%S") then
      return errors.json_error(400, "X-STC-Key-Id and X-STC-Session-Key are required; body key transport is unsupported")
    end
  end

  local request_payload
  if decrypt_request then
    local content_type = payload_codec.content_type(kong.request.get_header("Content-Type"))
    if not content_type then
      return errors.json_error(400, "DecryptRequest supports only application/json")
    end
    local body, err, status = size_limit.read_encrypted_request_body(config.max_body_bytes)
    if not body then
      return errors.json_error(status or 400, err)
    end
    local payload_err
    request_payload, payload_err = payload_codec.parse(body)
    if not request_payload then
      return errors.json_error(400, payload_err)
    end
  end

  local session_key
  if decrypt_request or encrypt_response then
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
    if encrypt_response then
      kong.ctx.plugin.session_key = session_key
    end
  end

  if decrypt_request then
    local plaintext, decrypt_err, _, error_status =
      crypto.decrypt_payload(request_payload, session_key)
    if not plaintext then
      kong.log.warn("Rejected encrypted request: ", decrypt_err)
      return errors.json_error(error_status or 400, decrypt_err)
    end

    kong.service.request.set_raw_body(plaintext)
  end

  kong.service.request.clear_header(headers.SESSION_KEY_HEADER)
  kong.service.request.clear_header(headers.KEY_ID_HEADER)
  kong.service.request.clear_header(headers.ENABLED_HEADER)
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
