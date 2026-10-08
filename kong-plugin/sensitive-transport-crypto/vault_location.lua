-- Vault address parsing helpers.

local VaultLocation = {}

function VaultLocation.parse(vault_addr)
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

return VaultLocation

