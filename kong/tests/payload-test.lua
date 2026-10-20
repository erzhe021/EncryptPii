local payload = require "kong.plugins.sensitive-transport-crypto.payload"
local cjson = require "cjson.safe"
local iv = "AAAAAAAAAAAAAAAA"
local data = "AAAAAAAAAAAAAAAAAAAAAA=="
local valid = '{"ivBase64":"' .. iv .. '","encryptedDataBase64":"' .. data .. '"}'
assert(payload.parse(valid).ivBase64 == iv)
assert(payload.parse(' \n' .. valid .. '\t '))
assert(payload.parse('{"\\u0069vBase64":"' .. iv .. '","encryptedDataBase64":"' .. data .. '"}'))
for _, invalid in ipairs({
  "", "null", "[]", "[" .. valid .. "]", valid .. valid, valid .. " true",
  valid:gsub("}$", ',"ivBase64":"' .. iv .. '"}'),
  '{"ivBase64":"' .. iv .. '","\\u0069vBase64":"' .. iv .. '"}',
  valid:gsub('"' .. iv .. '"', "12"),
  valid:gsub('"' .. iv .. '"', "null"),
  valid:gsub('"' .. iv .. '"', '""'),
  '{"ivBase64":"' .. iv .. '"}',
  valid:gsub("}$", ',"unknown":""}'),
  valid:gsub("}$", ",}"),
  (valid:gsub('"' .. iv .. '"', '"bad\\q"')),
}) do
  local result = payload.parse(invalid)
  assert(not result, invalid)
end
assert(payload.content_type("Application/JSON; charset=UTF-8") == "application/json")
assert(not payload.content_type(nil))
assert(not payload.content_type("text/json"))
assert(not payload.content_type("application/x-www-form-urlencoded"))

local cipher_names = {}
package.preload["resty.openssl.cipher"] = function()
  return { new = function(name)
    cipher_names[#cipher_names + 1] = name
    return {
      decrypt = function() return "decrypted" end,
      encrypt = function() return "encrypted" end,
      get_aead_tag = function() return string.rep("t", 16) end,
    }
  end }
end
package.preload["resty.openssl.rand"] = function()
  return { bytes = function() return string.rep("i", 12) end }
end
package.preload["resty.openssl.pkey"] = function()
  return { PADDINGS = { RSA_PKCS1_OAEP_PADDING = 4 } }
end
package.preload["kong.plugins.sensitive-transport-crypto.keys"] = function() return {} end
ngx = {
  decode_base64 = function(value)
    return ({ [iv] = string.rep("\0", 12), [data] = string.rep("\0", 16), AAAA = "\0\0\0" })[value]
  end,
  encode_base64 = function() return "encoded" end,
}
kong = { log = { err = function() end, warn = function() end } }
local crypto = require "kong.plugins.sensitive-transport-crypto.crypto"
for length, name in pairs({ [16] = "aes-128-gcm", [24] = "aes-192-gcm", [32] = "aes-256-gcm" }) do
  local key = string.rep("s", length)
  assert(crypto.decrypt_request_body(valid, key) == "decrypted")
  assert(cipher_names[#cipher_names] == name)
  assert(cjson.decode(crypto.encrypt_response(key, "plaintext")).ivBase64)
  assert(cipher_names[#cipher_names] == name)
end
for _, invalid in ipairs({ "A", "AA===", "AA=A", "AA==junk", "AA A", "AA\nA", "AAAA=" }) do
  local body = '{"ivBase64":"' .. iv .. '","encryptedDataBase64":' .. cjson.encode(invalid) .. '}'
  assert(not crypto.decrypt_request_body(body, string.rep("s", 32)), invalid)
end
assert(not crypto.decrypt_request_body(valid, string.rep("s", 15)))
assert(not crypto.decrypt_request_body(valid:gsub(iv, "AAAA"), string.rep("s", 32)))
assert(not crypto.decrypt_request_body(valid:gsub(data, "AAAA"), string.rep("s", 32)))
print("Payload and AES compatibility tests passed")
