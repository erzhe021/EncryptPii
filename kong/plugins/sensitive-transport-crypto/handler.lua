-- This plugin is designed to provide end-to-end encryption for sensitive data in transit.

local access = require "kong.plugins.sensitive-transport-crypto.access"
local response = require "kong.plugins.sensitive-transport-crypto.response"

-- The plugin supports the following features:
-- 1. Request Decryption: Decrypts incoming requests using session material from the request headers.
-- 2. Response Encryption: Encrypts outgoing responses using the same session key, ensuring that sensitive data remains protected during transit.
-- 3. Public Key Serving: Provides an endpoint to serve the public key used for encrypting session keys, allowing clients to encrypt data before sending it to the server.
local CryptoKongPlugin = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}

function CryptoKongPlugin:access(config)
  return access.run(config)
end

function CryptoKongPlugin:header_filter()
  return response.header_filter()
end

function CryptoKongPlugin:body_filter()
  return response.body_filter()
end

return CryptoKongPlugin
