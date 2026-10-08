-- Response-phase orchestration for the sensitive-transport-crypto plugin.

local crypto = require "kong.plugins.sensitive-transport-crypto.crypto"
local headers = require "kong.plugins.sensitive-transport-crypto.protocol"
local size_limit = require "kong.plugins.sensitive-transport-crypto.size_limit"

local Response = {}

local function should_encrypt_response()
  local ctx = kong.ctx.plugin
  if not ctx or not ctx.session_key then
    return false
  end
  if ctx.encrypt_response == false then
    return false
  end
  if ctx.plain_error_response == true then
    return false
  end
  return true
end

function Response.header_filter()
  local ctx = kong.ctx.plugin
  if not should_encrypt_response() then
    return
  end

  kong.response.clear_header("Content-Length")
  kong.response.clear_header("Content-Encoding")
  kong.response.clear_header("ETag")
  kong.response.clear_header("Content-MD5")
  kong.response.set_header("Content-Type", headers.CONTENT_TYPE_JSON)
  kong.response.set_header(headers.ENCRYPTED_RESPONSE_HEADER, "true")
  size_limit.begin_response_capture(ctx, ctx.max_body_bytes)
end

function Response.body_filter()
  local ctx = kong.ctx.plugin
  if not should_encrypt_response() then
    return
  end

  size_limit.capture_response_chunk(ctx, ngx.arg[1])

  ngx.arg[1] = ""
  if not ngx.arg[2] then
    return
  end

  if ctx.response_failed then
    ngx.status = 502
    ngx.header["Content-Type"] = headers.CONTENT_TYPE_JSON
    ngx.header[headers.ENCRYPTED_RESPONSE_HEADER] = "false"
    ngx.arg[1] = '{"message":"Upstream response exceeds the crypto plugin size limit"}'
    ngx.arg[2] = true
    return
  end

  local plaintext = size_limit.finish_response_capture(ctx)
  if plaintext == "" then
    return
  end

  local response_body = crypto.encrypt_response(ctx.session_key, plaintext)
  if not response_body then
    ngx.status = 502
    ngx.header["Content-Type"] = headers.CONTENT_TYPE_JSON
    ngx.header[headers.ENCRYPTED_RESPONSE_HEADER] = "false"
    ngx.arg[1] = '{"message":"Response encryption failed"}'
    ngx.arg[2] = true
    return
  end

  ngx.arg[1] = response_body
  ngx.arg[2] = true
end

return Response
