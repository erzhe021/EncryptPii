-- This module provides functions to interact with HashiCorp Vault for retrieving secrets.

local cjson = require "cjson.safe"
local http = require "resty.http"

local CONNECT_TIMEOUT_MS = 1000
local SEND_TIMEOUT_MS = 1000
local READ_TIMEOUT_MS = 2000
local TOKEN_CACHE_LIFETIME_RATIO = 0.8
local CONTENT_TYPE_JSON = "application/json"

local vault_token_cache = {}

local Vault = {}

local function parse_vault_location(vault_addr)
  local scheme, authority_and_path = vault_addr:match("^(https?)://(.+)$")
  local authority, base_path
  if authority_and_path then
    authority, base_path = authority_and_path:match("^([^/]+)(/.*)$")
    authority = authority or authority_and_path
  end
  local host, port
  if authority then
    host, port = authority:match("^([^:]+):?(%d*)$")
  end
  if not scheme or not host then
    return nil, "Invalid configured Vault address"
  end
  return {
    scheme = scheme,
    host = host,
    port = tonumber(port) or (scheme == "https" and 443 or 80),
    base_path = base_path and base_path ~= "/" and base_path or "",
  }
end

local function get_vault_token(config, location)
  if type(config.vault_auth_role) ~= "string" or config.vault_auth_role == "" then
    kong.log.err("Kubernetes Vault auth requires a role")
    return nil, "Vault is unavailable"
  end
  local cache_key = location.host .. ":" .. location.port .. ":" .. config.vault_auth_role
  local cached = vault_token_cache[cache_key]
  if cached and cached.expires_at > ngx.now() then
    return cached.token
  end

  local jwt_file, open_err = io.open(config.vault_kubernetes_jwt_path, "r")
  if not jwt_file then
    kong.log.err("Unable to read the Kubernetes service-account JWT: ", open_err)
    return nil, "Vault is unavailable"
  end
  local jwt = jwt_file:read("*a")
  jwt_file:close()
  if not jwt or jwt == "" then
    kong.log.err("Kubernetes service-account JWT file is empty")
    return nil, "Vault is unavailable"
  end
  jwt = jwt:gsub("%s+$", "")

  local httpc = http.new()
  httpc:set_timeouts(CONNECT_TIMEOUT_MS, SEND_TIMEOUT_MS, READ_TIMEOUT_MS)
  local ok, connect_err = httpc:connect({
    scheme = location.scheme,
    host = location.host,
    port = location.port,
    ssl_verify = location.scheme == "https",
  })
  if not ok then
    kong.log.err("Unable to connect to Vault for Kubernetes login: ", connect_err)
    return nil, "Vault is unavailable"
  end

  local request_body, encode_err = cjson.encode({
    role = config.vault_auth_role,
    jwt = jwt,
  })
  if not request_body then
    kong.log.err("Unable to encode the Vault Kubernetes login request: ", encode_err)
    httpc:close()
    return nil, "Vault is unavailable"
  end
  local response, request_err = httpc:request({
    method = "POST",
    path = location.base_path .. "/v1/auth/kubernetes/login",
    headers = {
      ["Content-Type"] = CONTENT_TYPE_JSON,
      ["Accept"] = CONTENT_TYPE_JSON,
    },
    body = request_body,
  })
  if not response then
    kong.log.err("Vault Kubernetes login request failed: ", request_err)
    httpc:close()
    return nil, "Vault is unavailable"
  end
  local response_body, body_err = response:read_body()
  httpc:close()
  local decoded, decode_err
  if response_body then
    decoded, decode_err = cjson.decode(response_body)
  end
  local token = decoded and decoded.auth and decoded.auth.client_token
  local lease_duration = decoded and tonumber(decoded.auth and decoded.auth.lease_duration)
  if response.status ~= 200 or type(token) ~= "string" or token == ""
    or not lease_duration or lease_duration <= 0 then
    kong.log.err("Vault Kubernetes login returned HTTP ", response.status, ": ",
      body_err or decode_err or "missing token or lease duration")
    return nil, "Vault is unavailable"
  end

  vault_token_cache[cache_key] = {
    token = token,
    expires_at = ngx.now() + lease_duration * TOKEN_CACHE_LIFETIME_RATIO,
  }
  return token
end

local function get_vault_json(token, location, path)
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

function Vault.get_context(config)
  local location, location_err = parse_vault_location(config.vault_addr)
  if not location then
    kong.log.err(location_err)
    return nil, "Vault is unavailable"
  end

  local token, token_err = get_vault_token(config, location)
  if not token then
    return nil, token_err
  end
  return {
    location = location,
    token = token,
  }
end

function Vault.get_json(context, path)
  return get_vault_json(context.token, context.location, path)
end

return Vault
