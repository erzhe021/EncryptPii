local headers = {}
local request_body
local forwarded_body
local cleared_headers = {}
local captured_key_id
local captured_encrypted_session_key

package.preload["cjson.safe"] = function()
  return {
    decode = function(body)
      local payload = {}
      for field, value in body:gmatch('"([^"]+)"%s*:%s*"([^"]*)"') do
        payload[field] = value
      end
      return next(payload) and payload or nil, "invalid test json"
    end,
  }
end

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
    get_private_key = function(_, key_id)
      captured_key_id = key_id
      return {
        decrypt = function(_, encrypted)
          captured_encrypted_session_key = encrypted
          return string.rep("s", 32)
        end,
      }
    end,
    get_public_key_response = function()
      return { keyId = "alias:2" }
    end,
  }
end

ngx = {
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
    get_header = function(name) return headers[name] end,
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
      set_header = function() end,
      set_path = function() end,
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
  decrypt_request = true,
  encrypt_response = true,
  max_body_bytes = 1024,
  upstream_auth_token = "upstream-token",
  upstream_path = "/upstream",
}
headers["X-STC-Key-Id"] = "alias:1"
headers["X-STC-Session-Key"] = encrypted_session_key
headers["Content-Length"] = tostring(#valid_body)
request_body = valid_body
exited = nil
kong.ctx.plugin = {}
local result = plugin:access(encrypted_config)
assert(result == nil)
assert(captured_key_id == "alias:1")
assert(captured_encrypted_session_key ~= nil)
assert(forwarded_body == "decrypted request")
assert(cleared_headers["X-STC-Key-Id"] and cleared_headers["X-STC-Session-Key"])

headers["X-STC-Key-Id"] = "alias:1"
headers["X-STC-Session-Key"] = encrypted_session_key
headers["Content-Length"] = nil
request_body = '{"data":"plaintext request"}'
forwarded_body = nil
cleared_headers = {}
kong.ctx.plugin = {}
result = plugin:access({
  decrypt_request = false,
  encrypt_response = true,
  upstream_auth_token = "upstream-token",
  upstream_path = "/response-only",
})
assert(result == nil)
assert(forwarded_body == nil, "response-only mode must preserve its plaintext request body")
assert(kong.ctx.plugin.session_key == string.rep("s", 32))
assert(cleared_headers["X-STC-Key-Id"] and cleared_headers["X-STC-Session-Key"])

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
  assert(result.body.message:find("session key fields are forbidden in the request body", 1, true),
    result.body.message)
end

headers["X-STC-Session-Key"] = nil
request_body = valid_body
headers["Content-Length"] = tostring(#request_body)
exited = nil
kong.ctx.plugin = {}
result = plugin:access(encrypted_config)
assert(result.status == 400)
assert(result.body.message ==
  "X-STC-Key-Id and X-STC-Session-Key are required; body key transport is unsupported")

print("Header transport tests passed")
