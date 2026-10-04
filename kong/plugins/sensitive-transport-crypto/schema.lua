local typedefs = require "kong.db.schema.typedefs"

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
          { vault_kubernetes_jwt_path = { type = "string", default = "/var/run/secrets/kubernetes.io/serviceaccount/token" } },
          { vault_secret_path = { type = "string", required = true, match = [[^[%w/_-]+$]] } },
          { key_alias = { type = "string", required = true, match = [[^[%w_-]+$]] } },
          { key_validity_millis = { type = "integer", default = 60000, between = { 1, 31536000000 } } },
          { key_grace_period_millis = { type = "integer", default = 30000, between = { 0, 31536000000 } } },
          { upstream_path = { type = "string", required = true, match = [[^/[%w/_-]*$]] } },
          { upstream_auth_token = { type = "string", required = true, referenceable = true } },
          { decrypt_request = { type = "boolean", default = false } },
          { encrypt_response = { type = "boolean", default = false } },
          { serve_public_key = { type = "boolean", default = false } },
          { session_key_source = { type = "string", default = "body", one_of = { "body", "header" } } },
          { max_body_bytes = { type = "integer", default = 1048576, between = { 1, 16777216 } } },
        },
      },
    },
  },
}
