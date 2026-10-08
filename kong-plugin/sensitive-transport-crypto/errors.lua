-- Centralized JSON error helpers for the sensitive-transport-crypto plugin.

local protocol = require "kong.plugins.sensitive-transport-crypto.protocol"
local keys = require "kong.plugins.sensitive-transport-crypto.keys"

local Errors = {}

local function exit_with_plain_flag(status, body, extra_headers)
    kong.ctx.plugin = kong.ctx.plugin or {}
    kong.ctx.plugin.encrypt_response = false
    kong.ctx.plugin.plain_error_response = true
    kong.ctx.plugin.session_key = nil
    kong.ctx.plugin.response_failed = nil

    local headers = {
        ["X-STC-Encrypted"] = "false",
    }
    if type(extra_headers) == "table" then
        for k, v in pairs(extra_headers) do
            headers[k] = v
        end
    end
    return kong.response.exit(status, body, headers)
end

function Errors.json_error(status, message)
    return exit_with_plain_flag(status, {
    message = message,
  })
end

function Errors.json_key_error(status, code, message, data)
    return exit_with_plain_flag(status, {
    code = code,
    msg = message,
    data = data,
  }, {
    ["Cache-Control"] = "no-store",
  })
end

function Errors.invalid_key_response()
    return Errors.json_key_error(400, protocol.INVALID_KEY_CODE, "Invalid key")
end

function Errors.expired_key_response(config)
  local latest_key, latest_key_err = keys.get_public_key_response(config)
  if not latest_key then
    kong.log.err("Unable to include the latest public key in expired-key response: ", latest_key_err)
    return Errors.json_error(503, "Public key is unavailable")
  end
    return Errors.json_key_error(400, protocol.KEY_EXPIRED_CODE,
            "The key version has expired; please update to the new version specified in the 'data' field.", latest_key)
end

return Errors
