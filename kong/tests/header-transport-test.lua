local headers = {}
local request_body
local forwarded_body
local cleared_headers = {}
local forwarded_headers = {}
local forwarded_path
local captured_key_id
local captured_encrypted_session_key

package.preload["resty.openssl.pkey"] = function()
  return { PADDINGS = { RSA_PKCS1_OAEP_PADDING = 4 } }
end

package.preload["resty.openssl.cipher"] = function()
  return {
    new = function()
      return {
        decrypt = function()
          return "decrypted request"
        end,
      }
    end,
  }
end

package.preload["resty.openssl.rand"] = function()
  return { bytes = function() return string.rep("i", 12) end }
end

package.preload["kong.plugins.sensitive-transport-crypto.keys"] = function()
  return {
    get_cached_private_key = function() return nil end,
    get_private_key_candidates = function(_, key_id)
      captured_key_id = key_id
      return {{
        decrypt = function(_, encrypted)
          captured_encrypted_session_key = encrypted
          return string.rep("s", 32)
        end,
      }}
    end,
    get_public_key_response = function()
      return { keyId = "alias:2" }
    end,
  }
end

ngx = {
  now = function() return 1000 end,
  arg = {},
  header = {},
  decode_base64 = function(value)
    return (ngx.decode_base64_impl or function(input)
      local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
      local output = {}
      local buffer = 0
      local bits = 0
      for index = 1, #input do
        local char = input:sub(index, index)
        if char ~= "=" then
          local position = alphabet:find(char, 1, true)
          if not position then return nil end
          buffer = buffer * 64 + position - 1
          bits = bits + 6
          if bits >= 8 then
            bits = bits - 8
            output[#output + 1] = string.char(math.floor(buffer / 2 ^ bits) % 256)
            buffer = buffer % 2 ^ bits
          end
        end
      end
      return table.concat(output)
    end)(value)
  end,
}

local exited
kong = {
  log = { warn = function() end, err = function() end },
  request = {
    get_headers = function()
      local result = {}
      for name, value in pairs(headers) do result[name:lower()] = value end
      return result
    end,
    get_header = function(name) return headers[name] end,
    get_path = function() return "/test" end,
    get_raw_body = function() return request_body end,
  },
  response = {
    exit = function(status, body)
      exited = { status = status, body = body }
      return exited
    end,
  },
  service = {
    request = {
      set_raw_body = function(body) forwarded_body = body end,
      clear_header = function(name) cleared_headers[name] = true end,
      set_header = function(name, value) forwarded_headers[name] = value end,
      set_path = function(path) forwarded_path = path end,
    },
  },
  ctx = { plugin = {} },
  vault = { get = function() return "upstream-token" end },
}

local crypto = require "kong.plugins.sensitive-transport-crypto.crypto"
local plugin = require "kong.plugins.sensitive-transport-crypto.handler"
local valid_body = '{"ivBase64":"AAAAAAAAAAAAAAAA","encryptedDataBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}'
local encrypted_session_key = string.rep("A", 44)

local encrypted_config = {
  crypto_enabled = true,
  decrypt_request = true,
  encrypt_response = true,
  max_body_bytes = 1024,
  upstream_auth_token = "upstream-token",
  upstream_path = "/upstream",
}
headers["X-STC-Enabled"] = "true"
headers["X-STC-Key-Id"] = "alias:1"
headers["X-STC-Session-Key"] = encrypted_session_key
headers["Content-Length"] = tostring(#valid_body)
headers["Content-Type"] = "application/json"
request_body = valid_body
exited = nil
kong.ctx.plugin = {}
local result = plugin:access(encrypted_config)
assert(result == nil)
assert(captured_key_id == "alias:1")
assert(captured_encrypted_session_key ~= nil)
assert(forwarded_body == "decrypted request")
assert(cleared_headers["X-STC-Key-Id"] and cleared_headers["X-STC-Session-Key"]
  and cleared_headers["X-STC-Enabled"])
assert(forwarded_headers["X-Crypto-Gateway-Token"] == "upstream-token")
assert(forwarded_headers["Accept-Encoding"] == "identity")
assert(forwarded_path == "/upstream")

headers["X-STC-Enabled"] = "true"
headers["X-STC-Key-Id"] = "alias:1"
headers["X-STC-Session-Key"] = encrypted_session_key
headers["Content-Length"] = nil
request_body = '{"data":"plaintext request"}'
forwarded_body = nil
cleared_headers = {}
kong.ctx.plugin = {}
result = plugin:access({
  crypto_enabled = true,
  decrypt_request = false,
  encrypt_response = true,
  upstream_auth_token = "upstream-token",
  upstream_path = "/response-only",
})
assert(result == nil)
assert(forwarded_body == nil, "response-only mode must preserve its plaintext request body")
assert(kong.ctx.plugin.session_key == string.rep("s", 32))
assert(cleared_headers["X-STC-Key-Id"] and cleared_headers["X-STC-Session-Key"]
  and cleared_headers["X-STC-Enabled"])

headers = {}
headers["Content-Length"] = nil
request_body = '{"data":"plain request"}'
forwarded_body = nil
cleared_headers = {}
forwarded_headers = {}
forwarded_path = nil
kong.ctx.plugin = {}
result = plugin:access(encrypted_config)
assert(result == nil, "missing X-STC-Enabled must bypass route crypto")
assert(forwarded_body == nil, "plain bypass must not decrypt or replace the body")
assert(kong.ctx.plugin.session_key == nil and kong.ctx.plugin.encrypt_response == false)
assert(cleared_headers["X-STC-Key-Id"] and cleared_headers["X-STC-Session-Key"]
  and cleared_headers["X-STC-Enabled"])
assert(forwarded_headers["X-Crypto-Gateway-Token"] == "upstream-token")
assert(forwarded_headers["Accept-Encoding"] == "identity")
assert(forwarded_path == "/upstream", "plain bypass must preserve the configured upstream path")

headers = { ["X-STC-Enabled"] = "false" }
forwarded_body = nil
cleared_headers = {}
forwarded_headers = {}
forwarded_path = nil
kong.ctx.plugin = {}
result = plugin:access(encrypted_config)
assert(result == nil, "X-STC-Enabled: false must bypass route crypto")
assert(forwarded_body == nil and kong.ctx.plugin.encrypt_response == false)
assert(cleared_headers["X-STC-Enabled"])
assert(forwarded_headers["X-Crypto-Gateway-Token"] == "upstream-token")
assert(forwarded_path == "/upstream")

headers["X-STC-Enabled"] = "false"
headers["X-STC-Key-Id"] = "alias:1"
request_body = '{"data":"plain request"}'
exited = nil
kong.ctx.plugin = {}
result = plugin:access(encrypted_config)
assert(result.status == 400, "key headers must be rejected when crypto is disabled")
assert(result.body.message ==
  "X-STC-Key-Id and X-STC-Session-Key are only valid together with X-STC-Enabled: true")

for _, invalid_enabled in ipairs({
  "",
  " true",
  "false ",
  "true,false",
  "yes",
  { "true", "true" },
  { "true", "false" },
}) do
  headers = { ["X-STC-Enabled"] = invalid_enabled }
  exited = nil
  kong.ctx.plugin = {}
  result = plugin:access(encrypted_config)
  assert(result.status == 400, "malformed or repeated enable headers must be rejected")
end

headers = { ["X-STC-Enabled"] = "true" }
exited = nil
kong.ctx.plugin = {}
result = plugin:access({
  crypto_enabled = true,
  decrypt_request = false,
  encrypt_response = false,
  upstream_auth_token = "upstream-token",
  upstream_path = "/plain",
})
assert(result.status == 400, "enable=true must not be accepted on a route without crypto")

headers = {}
exited = nil
kong.ctx.plugin = {}
result = plugin:access({ serve_public_key = true, crypto_enabled = true })
assert(result.status == 200, "public-key endpoint must remain usable without X-STC-Enabled")

headers["X-STC-Enabled"] = { "true", "true" }
exited = nil
kong.ctx.plugin = {}
result = plugin:access({ serve_public_key = true, crypto_enabled = true })
assert(result.status == 400, "public-key endpoint must reject repeated enable headers")

headers = {
  ["X-STC-Enabled"] = "true",
  ["X-STC-Key-Id"] = "",
  ["X-STC-Session-Key"] = "",
}
exited = nil
kong.ctx.plugin = {}
result = plugin:access({ serve_public_key = true, crypto_enabled = true })
assert(result.status == 400, "public-key endpoint must reject empty supplied key material")

headers = {
  ["X-STC-Enabled"] = "true",
  ["X-STC-Key-Id"] = "alias:1",
  ["X-STC-Session-Key"] = encrypted_session_key,
  ["Content-Type"] = "application/json",
}
for _, legacy_fields in ipairs({
  '"keyId":"alias:1"',
  '"encryptedSessionKeyBase64":"' .. encrypted_session_key .. '"',
  '"keyId":"alias:1","encryptedSessionKeyBase64":"' .. encrypted_session_key .. '"',
}) do
  request_body = '{"ivBase64":"AAAAAAAAAAAAAAAA","encryptedDataBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",'
    .. legacy_fields .. '}'
  headers["Content-Length"] = tostring(#request_body)
  exited = nil
  kong.ctx.plugin = {}
  result = plugin:access(encrypted_config)
  assert(result.status == 400)
  assert(result.body.message:find("Request body may contain only ivBase64 and encryptedDataBase64", 1, true),
    result.body.message)
end

headers = { ["X-STC-Enabled"] = "true", ["X-STC-Key-Id"] = { "alias:1", "alias:1" } }
request_body = valid_body
exited = nil
kong.ctx.plugin = {}
result = plugin:access(encrypted_config)
assert(result.status == 400, "duplicate key headers must be rejected even when identical")

headers = { ["X-STC-Enabled"] = "true", ["X-STC-Key-Id"] = "alias:1",
  ["Content-Type"] = "application/json" }
request_body = valid_body
exited = nil
kong.ctx.plugin = {}
result = plugin:access(encrypted_config)
assert(result.status == 400, "missing session key must still be rejected when enabled")
assert(result.body.message ==
  "X-STC-Key-Id and X-STC-Session-Key are required; body key transport is unsupported")

headers = { ["X-STC-Enabled"] = "false", ["X-STC-Session-Key"] = "" }
exited = nil
kong.ctx.plugin = {}
result = plugin:access(encrypted_config)
assert(result.status == 400, "even an empty key header must be rejected when crypto is disabled")

for _, value in ipairs({ "TRUE", "True", "tRuE" }) do
  headers = {
    ["X-STC-Enabled"] = value, ["X-STC-Key-Id"] = "alias:1",
    ["X-STC-Session-Key"] = encrypted_session_key, ["Content-Type"] = "application/json",
  }
  request_body = valid_body
  assert(plugin:access(encrypted_config) == nil, "enable header must be case-insensitive")
end
for _, value in ipairs({ "FALSE", "False" }) do
  headers = { ["X-STC-Enabled"] = value }
  assert(plugin:access(encrypted_config) == nil)
  assert(not kong.ctx.plugin.encrypt_response)
end

headers = { ["X-STC-Enabled"] = "true" }
result = plugin:access({ crypto_enabled = false })
assert(result.status == 400 and result.body.message == "Server transport crypto is disabled.")
assert(result.body.timestamp == 1000000 and result.body.path == "/test"
  and result.body.error == "Bad Request")
assert(plugin:access({ serve_public_key = true, crypto_enabled = true }).status == 400,
  "public-key endpoint has no crypto annotations")
headers = {}
assert(plugin:access({ serve_public_key = true, crypto_enabled = false }).status == 404)

headers = {
  ["X-STC-Enabled"] = "true", ["X-STC-Key-Id"] = "alias:1",
  ["X-STC-Session-Key"] = encrypted_session_key,
  ["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8",
}
request_body = "ivBase64=AAAAAAAAAAAAAAAA&encryptedDataBase64=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
forwarded_body = nil
assert(plugin:access(encrypted_config) == nil)
assert(forwarded_body == "decrypted request")
for _, content_type in ipairs({ "", "text/plain", "application/json-patch+json", "multipart/form-data" }) do
  headers["Content-Type"] = content_type
  assert(plugin:access(encrypted_config).status == 400)
end
headers["Content-Type"] = nil
assert(plugin:access(encrypted_config).status == 400)

headers["Content-Type"] = "application/json"
for _, name in ipairs({ "X-STC-Key-Id", "X-STC-Session-Key" }) do
  local saved = headers[name]
  headers[name] = " \t"
  assert(plugin:access(encrypted_config).status == 400, "blank key headers must be rejected")
  headers[name] = saved
end

print("Header transport tests passed")
