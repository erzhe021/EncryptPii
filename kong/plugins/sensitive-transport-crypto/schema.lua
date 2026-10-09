-- This is the schema definition for the sensitive-transport-crypto plugin.

local typedefs = require "kong.db.schema.typedefs"

local DEFAULT_KUBERNETES_JWT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
local DEFAULT_KEY_VALIDITY_MILLIS = 60000
local DEFAULT_KEY_GRACE_PERIOD_MILLIS = 30000
local DEFAULT_ROTATION_BEFORE_EXPIRY_MILLIS = 40000
local MAX_KEY_PERIOD_MILLIS = 31536000000
local DEFAULT_MAX_BODY_BYTES = 1048576
local MAX_BODY_BYTES = 16777216

return {
  name = "sensitive-transport-crypto",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          { vault_addr = { type = "string", required = true } },
          { vault_auth_role = { type = "string", required = true, match = [[^[%w_-]+$]] } },
          { vault_kubernetes_jwt_path = { type = "string", default = DEFAULT_KUBERNETES_JWT_PATH } },
          { vault_secret_path = { type = "string", required = true, match = [[^[%w/_-]+$]] } },
          { key_alias = { type = "string", required = true, match = [[^[%w_-]+$]] } },
          { key_validity_millis = { type = "integer", default = DEFAULT_KEY_VALIDITY_MILLIS, between = { 1, MAX_KEY_PERIOD_MILLIS } } },
          { key_grace_period_millis = { type = "integer", default = DEFAULT_KEY_GRACE_PERIOD_MILLIS, between = { 0, MAX_KEY_PERIOD_MILLIS } } },
          { rotation_before_expiry_millis = { type = "integer", default = DEFAULT_ROTATION_BEFORE_EXPIRY_MILLIS, between = { 0, MAX_KEY_PERIOD_MILLIS } } },
          { upstream_path = { type = "string", required = true, match = [[^/[%w/_-]*$]] } },
          { upstream_auth_token = { type = "string", required = true, referenceable = true } },
          { decrypt_request = { type = "boolean", default = false } },
          { encrypt_response = { type = "boolean", default = false } },
          { serve_public_key = { type = "boolean", default = false } },
          { max_body_bytes = { type = "integer", default = DEFAULT_MAX_BODY_BYTES, between = { 1, MAX_BODY_BYTES } } },
        },
      },
    },
  },
}
