-- Shared protocol constants for the sensitive-transport-crypto plugin.

local Protocol = {
  -- Transport headers.
  KEY_ID_HEADER = "X-STC-Key-Id",
  SESSION_KEY_HEADER = "X-STC-Session-Key",
  GATEWAY_TOKEN_HEADER = "X-Crypto-Gateway-Token",
  ENCRYPTED_RESPONSE_HEADER = "X-STC-Encrypted",

  -- Payload / response encoding.
  CONTENT_TYPE_JSON = "application/json",

  -- Protocol error codes.
  KEY_EXPIRED_CODE = "KEY_EXPIRED",
  INVALID_KEY_CODE = "INVALID_KEY",
}

return Protocol
