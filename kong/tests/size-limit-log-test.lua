local logs = {}
local headers = {}
local request_body
local raw_body_reads = 0

package.preload["kong.plugins.sensitive-transport-crypto.crypto"] = function() return {} end
package.preload["kong.plugins.sensitive-transport-crypto.keys"] = function() return {} end

local function capture(level, ...)
  local parts = { ... }
  for i, value in ipairs(parts) do
    parts[i] = tostring(value)
  end
  logs[#logs + 1] = { level = level, message = table.concat(parts) }
end

kong = {
  log = {
    warn = function(...) capture("warn", ...) end,
    err = function(...) capture("err", ...) end,
  },
  request = {
    get_header = function(name) return headers[name] end,
    get_raw_body = function()
      raw_body_reads = raw_body_reads + 1
      return request_body
    end,
  },
  response = {
    exit = function(status, body) return { status = status, body = body } end,
  },
  ctx = { plugin = {} },
}
ngx = { arg = {}, header = {} }

local plugin = require "kong.plugins.sensitive-transport-crypto.handler"
local config = { decrypt_request = true, max_body_bytes = 4 }

headers["Content-Length"] = "5"
local result = plugin:access(config)
assert(result.status == 413)
assert(raw_body_reads == 0)
assert(#logs == 1 and logs[1].level == "warn")
assert(logs[1].message:find("bytes=5, limit=4", 1, true))

logs = {}
headers = {}
request_body = "secret"
result = plugin:access(config)
assert(result.status == 413)
assert(#logs == 1 and logs[1].level == "warn")
assert(logs[1].message:find("bytes=6, limit=4", 1, true))
assert(not logs[1].message:find(request_body, 1, true))

logs = {}
kong.ctx.plugin = {
  session_key = "test-session-key",
  max_body_bytes = 4,
  response_chunks = {},
  response_bytes = 0,
}
ngx.arg = { "abc", false }
plugin:body_filter()
assert(#logs == 0)
ngx.arg = { "def", false }
plugin:body_filter()
assert(#logs == 1 and logs[1].level == "err")
assert(logs[1].message:find("bytes=6, limit=4", 1, true))
ngx.arg = { "ghi", true }
plugin:body_filter()
assert(#logs == 1, "Response overflow must be logged only once per request")
assert(ngx.arg[1] == '{"message":"Upstream response exceeds the crypto plugin size limit"}')
assert(not logs[1].message:find("test-session-key", 1, true))
assert(not logs[1].message:find("def", 1, true))

print("Size-limit logging tests passed")
