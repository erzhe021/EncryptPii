local cjson = require "cjson.safe"

local Payload = {}
local FIELDS = { ivBase64 = true, encryptedDataBase64 = true }

local function parse_json(body)
  local position = 1
  local function whitespace()
    local _, last = body:find("^[ \t\r\n]*", position)
    position = (last or position - 1) + 1
  end
  local function token(expected)
    whitespace()
    if body:sub(position, position) ~= expected then
      return false
    end
    position = position + 1
    return true
  end
  local function string_value()
    whitespace()
    if body:sub(position, position) ~= '"' then
      return nil
    end
    local start = position
    position = position + 1
    while position <= #body do
      local char = body:sub(position, position)
      if char == '"' then
        position = position + 1
        return cjson.decode(body:sub(start, position - 1))
      end
      position = position + (char == "\\" and 2 or 1)
    end
  end

  if not token("{") then
    return nil
  end
  local fields = {}
  for index = 1, 2 do
    local name = string_value()
    if not name or fields[name] ~= nil or not token(":") then
      return nil
    end
    local value = string_value()
    if type(value) ~= "string" then
      return nil
    end
    fields[name] = value
    if index == 1 and not token(",") then
      return nil
    end
  end
  if not token("}") then
    return nil
  end
  whitespace()
  if position <= #body then
    return nil
  end
  return fields
end

local function url_decode(value)
  if value:gsub("%%[0-9a-fA-F][0-9a-fA-F]", ""):find("%%") then
    return nil
  end
  return (value:gsub("+", " "):gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end))
end

local function parse_form(body)
  local fields = {}
  for pair in (body .. "&"):gmatch("(.-)&") do
    local name, value = pair:match("^([^=]*)=(.*)$")
    if not name then
      return nil
    end
    name, value = url_decode(name), url_decode(value)
    if not name or not value or fields[name] ~= nil then
      return nil
    end
    fields[name] = value
  end
  return fields
end

function Payload.content_type(value)
  if type(value) ~= "string" then
    return nil
  end
  local media_type = value:match("^%s*([^;]+)")
  media_type = media_type and media_type:gsub("%s+$", ""):lower()
  if media_type == "application/json" or media_type == "application/x-www-form-urlencoded" then
    return media_type
  end
end

function Payload.parse(body, content_type)
  if type(body) ~= "string" or body == "" then
    return nil, "Encrypted request body is required."
  end
  local fields
  if content_type == "application/x-www-form-urlencoded" then
    fields = parse_form(body)
  elseif content_type == "application/json" then
    fields = parse_json(body)
  else
    return nil, "DecryptRequest supports only application/json and application/x-www-form-urlencoded"
  end
  if not fields then
    return nil, "Request body may contain only ivBase64 and encryptedDataBase64"
  end
  local count = 0
  for name in pairs(fields) do
    if not FIELDS[name] then
      return nil, "Request body may contain only ivBase64 and encryptedDataBase64"
    end
    count = count + 1
  end
  if count ~= 2 then
    return nil, "Request body may contain only ivBase64 and encryptedDataBase64"
  end
  if fields.ivBase64 == "" or fields.encryptedDataBase64 == "" then
    return nil, "IV and encrypted data are required."
  end
  return fields
end

return Payload
