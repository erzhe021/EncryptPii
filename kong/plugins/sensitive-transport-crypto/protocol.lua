-- Shared protocol constants for the sensitive-transport-crypto plugin.

local Protocol = {
  -- Transport headers.
  KEY_ID_HEADER = "X-STC-KEY-ID",
  SESSION_KEY_HEADER = "X-STC-SESSION-KEY",
  GATEWAY_TOKEN_HEADER = "X-Crypto-Gateway-Token",

  -- Payload / response encoding.
  CONTENT_TYPE_JSON = "application/json",

  -- Protocol error codes.
  KEY_EXPIRED_CODE = "KEY_EXPIRED",
  INVALID_KEY_CODE = "INVALID_KEY",
}

return Protocol
