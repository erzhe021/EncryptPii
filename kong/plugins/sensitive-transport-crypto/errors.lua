-- Centralized JSON error helpers for the sensitive-transport-crypto plugin.

local protocol = require "kong.plugins.sensitive-transport-crypto.protocol"
local keys = require "kong.plugins.sensitive-transport-crypto.keys"
local cjson = require "cjson.safe"

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
    local reasons = {
        [400] = "Bad Request", [404] = "Not Found", [413] = "Payload Too Large",
        [500] = "Internal Server Error", [502] = "Bad Gateway", [503] = "Service Unavailable",
    }
    return exit_with_plain_flag(status, {
    timestamp = math.floor(ngx.now() * 1000),
    status = status,
    error = reasons[status],
    message = status == 500 and "Cryptographic service internal error" or message,
    path = kong.request.get_path(),
  })
end

function Errors.json_key_error(status, code, message, data)
    return exit_with_plain_flag(status, {
    code = code,
    msg = message,
    data = data or cjson.null,
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
    return Errors.json_error(500, "Public key is unavailable")
  end
    return Errors.json_key_error(400, protocol.KEY_EXPIRED_CODE,
            "The key version has expired; please update to the new version specified in the 'data' field.", latest_key)
end

return Errors
