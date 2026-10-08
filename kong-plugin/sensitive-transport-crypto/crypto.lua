-- This module provides functions for decrypting request payloads and encrypting response payloads

local cjson = require "cjson.safe"
local cipher = require "resty.openssl.cipher"
local pkey = require "resty.openssl.pkey"
local random = require "resty.openssl.rand"
local keys = require "kong.plugins.sensitive-transport-crypto.keys"

local GCM_IV_BYTES = 12
local GCM_TAG_BYTES = 16
local AES_KEY_BYTES = 32
local AES_GCM_CIPHER = "aes-256-gcm"
local OAEP_OPTIONS = {
  oaep_md = "sha256",
  -- The Java SDK uses the JCA default MGF1 digest for this transformation.
  mgf1_md = "sha1",
}

local Crypto = {}

local function decode_base64(value, field_name)
  if type(value) ~= "string" or value == "" then
    return nil, field_name .. " is required"
  end

  local decoded = ngx.decode_base64(value)
  if not decoded then
    return nil, field_name .. " must be valid base64"
  end

  return decoded
end

function Crypto.decrypt_session_key(config, key_id, encrypted_session_key_base64)
  if type(key_id) ~= "string" or key_id == "" then
    return nil, "keyId is required"
  end

  local encrypted_session_key, decode_err =
    decode_base64(encrypted_session_key_base64, "encrypted session key")
  if not encrypted_session_key then
    return nil, decode_err
  end

  local private_key, key_err, key_status, key_error_code = keys.get_private_key(config, key_id)
  if not private_key then
    return nil, key_err, key_status or 503, key_error_code
  end

  local session_key, rsa_err = private_key:decrypt(
    encrypted_session_key,
    pkey.PADDINGS.RSA_PKCS1_OAEP_PADDING,
    OAEP_OPTIONS
  )
  if not session_key then
    kong.log.warn("Failed to decrypt request session key: ", rsa_err)
    return nil, "request session key could not be decrypted"
  end
  if #session_key ~= AES_KEY_BYTES then
    return nil, "decrypted session key must be 32 bytes"
  end
  return session_key
end

function Crypto.decrypt_request_body(body, session_key)
  local payload, err = cjson.decode(body)
  if not payload or type(payload) ~= "table" then
    return nil, err or "request body must be a JSON object"
  end

  if payload.keyId ~= nil or payload.encryptedSessionKeyBase64 ~= nil then
    return nil, "session key fields are forbidden in the request body; use X-STC-Key-Id and X-STC-Session-Key"
  end
  for field in pairs(payload) do
    if field ~= "ivBase64" and field ~= "encryptedDataBase64" then
      return nil, "request body may contain only ivBase64 and encryptedDataBase64"
    end
  end

  local iv, iv_err = decode_base64(payload.ivBase64, "ivBase64")
  if not iv then
    return nil, iv_err
  end
  if #iv ~= GCM_IV_BYTES then
    return nil, "ivBase64 must decode to a 12-byte IV"
  end

  local encrypted_data, data_err =
    decode_base64(payload.encryptedDataBase64, "encryptedDataBase64")
  if not encrypted_data then
    return nil, data_err
  end
  if #encrypted_data < GCM_TAG_BYTES then
    return nil, "encryptedDataBase64 is too short"
  end

  if type(session_key) ~= "string" or #session_key ~= AES_KEY_BYTES then
    return nil, "decrypted session key must be 32 bytes"
  end

  local ciphertext = encrypted_data:sub(1, -GCM_TAG_BYTES - 1)
  local tag = encrypted_data:sub(-GCM_TAG_BYTES)
  local aes, aes_err = cipher.new(AES_GCM_CIPHER)
  if not aes then
    kong.log.err("Unable to initialize AES-GCM: ", aes_err)
    return nil, "request decryption is unavailable", nil, 500
  end

  local plaintext, decrypt_err = aes:decrypt(session_key, iv, ciphertext, false, nil, tag)
  if not plaintext then
    kong.log.warn("Failed to authenticate or decrypt request payload: ", decrypt_err)
    return nil, "request payload authentication failed"
  end

  return plaintext, nil, session_key
end

function Crypto.encrypt_response(session_key, plaintext)
  local iv, random_err = random.bytes(GCM_IV_BYTES, true)
  if not iv then
    kong.log.err("Unable to generate response IV: ", random_err)
    return nil
  end

  local aes, cipher_err = cipher.new(AES_GCM_CIPHER)
  if not aes then
    kong.log.err("Unable to initialize response AES-GCM: ", cipher_err)
    return nil
  end

  local ciphertext, encrypt_err = aes:encrypt(session_key, iv, plaintext)
  if not ciphertext then
    kong.log.err("Unable to encrypt upstream response: ", encrypt_err)
    return nil
  end

  local tag, tag_err = aes:get_aead_tag(GCM_TAG_BYTES)
  if not tag then
    kong.log.err("Unable to obtain response AES-GCM tag: ", tag_err)
    return nil
  end

  local response_body, encode_err = cjson.encode({
    ivBase64 = ngx.encode_base64(iv),
    encryptedDataBase64 = ngx.encode_base64(ciphertext .. tag),
  })
  if not response_body then
    kong.log.err("Unable to encode encrypted response: ", encode_err)
    return nil
  end
  return response_body
end

return Crypto
