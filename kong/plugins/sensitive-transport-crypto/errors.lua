-- Centralized JSON error helpers for the sensitive-transport-crypto plugin.

local headers = require "kong.plugins.sensitive-transport-crypto.protocol"
local keys = require "kong.plugins.sensitive-transport-crypto.keys"

local Errors = {}

function Errors.json_error(status, message)
  return kong.response.exit(status, {
    message = message,
  })
end

function Errors.json_key_error(status, code, message, data)
  return kong.response.exit(status, {
    code = code,
    msg = message,
    data = data,
  }, {
    ["Cache-Control"] = "no-store",
  })
end

function Errors.invalid_key_response()
  return Errors.json_key_error(400, headers.INVALID_KEY_CODE, "keyId中的keyAlias无效")
end

function Errors.expired_key_response(config)
  local latest_key, latest_key_err = keys.get_public_key_response(config)
  if not latest_key then
    kong.log.err("Unable to include the latest public key in expired-key response: ", latest_key_err)
    return Errors.json_error(503, "Public key is unavailable")
  end
  return Errors.json_key_error(400, headers.KEY_EXPIRED_CODE,
    "密钥版本已过期，请更新。新版本在data字段里。", latest_key)
end

return Errors

