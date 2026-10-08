-- This module provides functions to interact with HashiCorp Vault for retrieving secrets.

local vault_auth = require "kong.plugins.sensitive-transport-crypto.vault_auth"
local vault_location = require "kong.plugins.sensitive-transport-crypto.vault_location"
local vault_request = require "kong.plugins.sensitive-transport-crypto.vault_request"

local Vault = {}

function Vault.get_context(config)
  local location, location_err = vault_location.parse(config.vault_addr)
  if not location then
    kong.log.err(location_err)
    return nil, "Vault is unavailable"
  end

  local token, token_err = vault_auth.get_token(config, location)
  if not token then
    return nil, token_err
  end
  return {
    location = location,
    token = token,
  }
end

function Vault.get_json(context, path)
  return vault_request.get_json(context.token, context.location, path)
end

return Vault
