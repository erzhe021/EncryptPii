-- Parsing helpers for Vault key metadata and key material.

local pkey = require "resty.openssl.pkey"

local MILLIS_PER_SECOND = 1000

local KeyParser = {}

function KeyParser.parse_vault_created_time(value)
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

function KeyParser.parse_private_key(private_key_base64, key_id)
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
  return key
end

return KeyParser

