-- Parsing helpers for Vault key metadata and key material.

local pkey = require "resty.openssl.pkey"

local MILLIS_PER_SECOND = 1000

local KeyParser = {}

function KeyParser.parse_vault_created_time(value)
  if type(value) ~= "string" then
    return nil
  end
  local year, month, day, hour, minute, second, fraction =
    value:match("^(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)(.*)Z$")
  if not year or (fraction ~= "" and not fraction:match("^%.%d%d?%d?%d?%d?%d?%d?%d?%d?$")) then
    return nil
  end
  year, month, day = tonumber(year), tonumber(month), tonumber(day)
  hour, minute, second = tonumber(hour), tonumber(minute), tonumber(second)
  local leap = year % 4 == 0 and (year % 100 ~= 0 or year % 400 == 0)
  local month_days = { 31, leap and 29 or 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
  if not month_days[month] or day < 1 or day > month_days[month]
      or hour > 23 or minute > 59 or second > 59 then
    return nil
  end
  -- Civil-date conversion avoids os.time's dependence on the worker's timezone.
  local adjusted_year = year - (month <= 2 and 1 or 0)
  local era = math.floor(adjusted_year / 400)
  local year_of_era = adjusted_year - era * 400
  local adjusted_month = month + (month > 2 and -3 or 9)
  local day_of_year = math.floor((153 * adjusted_month + 2) / 5) + day - 1
  local days = era * 146097 + year_of_era * 365 + math.floor(year_of_era / 4)
    - math.floor(year_of_era / 100) + day_of_year - 719468
  local millis = math.floor((tonumber("0" .. fraction) or 0) * MILLIS_PER_SECOND)
  return (days * 86400 + hour * 3600 + minute * 60 + second) * MILLIS_PER_SECOND + millis
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
