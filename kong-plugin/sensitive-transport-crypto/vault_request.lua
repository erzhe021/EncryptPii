-- Vault JSON request helpers.

local cjson = require "cjson.safe"
local http = require "resty.http"

local CONNECT_TIMEOUT_MS = 1000
local SEND_TIMEOUT_MS = 1000
local READ_TIMEOUT_MS = 2000
local CONTENT_TYPE_JSON = "application/json"

local VaultRequest = {}

function VaultRequest.get_json(token, location, path)
  local httpc = http.new()
  httpc:set_timeouts(CONNECT_TIMEOUT_MS, SEND_TIMEOUT_MS, READ_TIMEOUT_MS)
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
      ["Accept"] = CONTENT_TYPE_JSON,
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

return VaultRequest

