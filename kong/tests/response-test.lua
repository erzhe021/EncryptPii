local cjson = require "cjson.safe"
local active_key = { keyId = "alias:2" }
local should_fail = false
package.loaded["kong.plugins.sensitive-transport-crypto.crypto"] = {
  encrypt_response = function(_, plaintext)
    return cjson.encode({ ivBase64 = "iv", encryptedDataBase64 = "cipher:" .. plaintext })
  end,
}
package.loaded["kong.plugins.sensitive-transport-crypto.keys"] = {
  get_public_key_response = function()
    if should_fail then return nil, "test failure" end
    return active_key
  end,
}
local response_headers
ngx = { now = function() return 1000 end, arg = {}, header = {} }
kong = {
  ctx = { plugin = {} },
  log = { err = function() end, warn = function() end },
  request = { get_path = function() return "/response-test" end },
  response = {
    clear_header = function(name) response_headers[name] = nil end,
    set_header = function(name, value) response_headers[name] = value end,
    exit = function(status, body, headers) return { status = status, body = body, headers = headers } end,
  },
}
local response = require "kong.plugins.sensitive-transport-crypto.response"
for _, status in ipairs({ 200, 400, 500 }) do
  ngx.status = status
  response_headers = { ["Content-Length"] = "20", ["Content-Encoding"] = "gzip", ETag = "old" }
  kong.ctx.plugin = { encrypt_response = true, session_key = "key", max_body_bytes = 1024 }
  response.header_filter()
  assert(response_headers["X-STC-Encrypted"] == "true")
  assert(not response_headers["Content-Length"] and not response_headers["Content-Encoding"]
    and not response_headers.ETag)
  ngx.arg = { '{"message":', false }
  response.body_filter()
  assert(ngx.arg[1] == "")
  ngx.arg = { '"business error"}', true }
  response.body_filter()
  assert(cjson.decode(ngx.arg[1]).encryptedDataBase64 == 'cipher:{"message":"business error"}')
  assert(ngx.status == status, "upstream status must survive response encryption")
end
for _, context in ipairs({
  { encrypt_response = false },
  { encrypt_response = false, session_key = "key" },
  { encrypt_response = true, session_key = "key", plain_error_response = true },
}) do
  kong.ctx.plugin = context
  response_headers = {}
  response.header_filter()
  ngx.arg = { "plaintext", true }
  response.body_filter()
  assert(ngx.arg[1] == "plaintext" and not response_headers["X-STC-Encrypted"])
end
local errors = require "kong.plugins.sensitive-transport-crypto.errors"
local expired = errors.expired_key_response({})
assert(expired.status == 400 and expired.body.code == "KEY_EXPIRED" and expired.body.data == active_key)
assert(expired.headers["X-STC-Encrypted"] == "false" and expired.headers["Cache-Control"] == "no-store")
local invalid = errors.invalid_key_response()
assert(invalid.status == 400 and invalid.body.code == "INVALID_KEY" and invalid.body.data == cjson.null)
assert(invalid.headers["Cache-Control"] == "no-store")
should_fail = true
local unavailable = errors.expired_key_response({})
assert(unavailable.status == 500 and unavailable.body.message == "Cryptographic service internal error")
assert(unavailable.body.timestamp == 1000000 and unavailable.body.status == 500
  and unavailable.body.error == "Internal Server Error" and unavailable.body.path == "/response-test")
assert(kong.ctx.plugin.plain_error_response and not kong.ctx.plugin.session_key)
print("Response mode, status and error contract tests passed")
