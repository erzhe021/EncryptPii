local cjson = require "cjson.safe"
local pkey = require "resty.openssl.pkey"
local cipher = require "resty.openssl.cipher"
local rand = require "resty.openssl.rand"
local rsa = assert(pkey.new({ type = "RSA", bits = 2048 }))
local other_rsa = assert(pkey.new({ type = "RSA", bits = 2048 }))
local candidates = { rsa }
local deferred_error, deferred_status, deferred_code
local cached_key
local resolution_calls = 0
package.loaded["kong.plugins.sensitive-transport-crypto.keys"] = {
  get_cached_private_key = function() return cached_key end,
  get_private_key_candidates = function()
    resolution_calls = resolution_calls + 1
    return candidates, deferred_error, deferred_status, deferred_code
  end,
}
kong = { log = { err = function() end, warn = function() end } }
local crypto = require "kong.plugins.sensitive-transport-crypto.crypto"
local oaep = { oaep_md = "sha256", mgf1_md = "sha1" }
local padding = pkey.PADDINGS.RSA_PKCS1_OAEP_PADDING
local plaintext = '{"name":"Alice Smith","phone":"123+456"}'

for _, length in ipairs({ 16, 24, 32 }) do
  local key = assert(rand.bytes(length, true))
  local encrypted_key = assert(rsa:encrypt(key, padding, oaep))
  local encoded_key = ngx.encode_base64(encrypted_key)
  candidates = { other_rsa, rsa }
  assert(crypto.decrypt_session_key({}, "alias:1", encoded_key) == key,
    "RSA decryption must try subsequent candidates")
  local iv = assert(rand.bytes(12, true))
  local aes = assert(cipher.new("aes-" .. length * 8 .. "-gcm"))
  local encrypted = assert(aes:encrypt(key, iv, plaintext))
  local tag = assert(aes:get_aead_tag(16))
  local payload = { ivBase64 = ngx.encode_base64(iv),
    encryptedDataBase64 = ngx.encode_base64(encrypted .. tag) }
  assert(crypto.decrypt_request_body(cjson.encode(payload), key, "application/json") == plaintext)
  local form = ngx.encode_args(payload)
  assert(crypto.decrypt_request_body(form, key, "application/x-www-form-urlencoded") == plaintext)
  local response = assert(cjson.decode(assert(crypto.encrypt_response(key, plaintext))))
  local response_iv = assert(ngx.decode_base64(response.ivBase64))
  local response_data = assert(ngx.decode_base64(response.encryptedDataBase64))
  local decipher = assert(cipher.new("aes-" .. length * 8 .. "-gcm"))
  assert(decipher:decrypt(key, response_iv, response_data:sub(1, -17), false, nil,
    response_data:sub(-16)) == plaintext)
  local tampered_tag = string.char((tag:byte(1) + 1) % 256) .. tag:sub(2)
  payload.encryptedDataBase64 = ngx.encode_base64(encrypted .. tampered_tag)
  assert(not crypto.decrypt_request_body(cjson.encode(payload), key, "application/json"))

  deferred_error, deferred_status, deferred_code = "stale", 400, "stale_key"
  assert(crypto.decrypt_session_key({}, "alias:999", encoded_key) == key,
    "stale keyId must not reject successfully decrypted session material")
  candidates = { other_rsa }
  local result, _, status, code = crypto.decrypt_session_key({}, "alias:999", encoded_key)
  assert(not result and status == 400 and code == "stale_key")
  deferred_error, deferred_status, deferred_code = nil, nil, nil
  result, _, status, code = crypto.decrypt_session_key({}, "alias:1", encoded_key)
  assert(not result and not status and not code, "wrong ciphertext is not a refresh signal")
end

local bad_key = ngx.encode_base64(assert(rsa:encrypt("bad", padding, oaep)))
candidates = { rsa }
assert(not crypto.decrypt_session_key({}, "alias:1", bad_key))
local wrong_mgf = ngx.encode_base64(assert(rsa:encrypt(string.rep("k", 32), padding,
  { oaep_md = "sha256", mgf1_md = "sha256" })))
assert(not crypto.decrypt_session_key({}, "alias:1", wrong_mgf))
cached_key = rsa
local calls_before = resolution_calls
local encoded_key = ngx.encode_base64(assert(rsa:encrypt(string.rep("k", 32), padding, oaep)))
assert(crypto.decrypt_session_key({}, "alias:1", encoded_key) == string.rep("k", 32))
assert(resolution_calls == calls_before, "valid cached key must work without Vault metadata I/O")
cached_key = other_rsa
assert(crypto.decrypt_session_key({}, "alias:1", encoded_key) == string.rep("k", 32))
print("Real RSA-OAEP/AES-GCM compatibility tests passed")
