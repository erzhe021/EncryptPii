-- Helpers for request and response size limits in the sensitive-transport-crypto plugin.

local SizeLimit = {}

function SizeLimit.read_encrypted_request_body(max_body_bytes)
  local content_length = tonumber(kong.request.get_header("Content-Length"))
  if content_length and content_length > max_body_bytes then
    kong.log.warn("Encrypted request Content-Length exceeds the crypto plugin size limit: bytes=",
      content_length, ", limit=", max_body_bytes)
    return nil, "Request body exceeds the crypto plugin size limit", 413
  end

  local body, err = kong.request.get_raw_body()
  if not body then
    kong.log.warn("Unable to read encrypted request body: ", err)
    return nil, "Encrypted request body is required", 400
  end
  if #body > max_body_bytes then
    kong.log.warn("Encrypted request body exceeds the crypto plugin size limit: bytes=",
      #body, ", limit=", max_body_bytes)
    return nil, "Request body exceeds the crypto plugin size limit", 413
  end
  return body
end

function SizeLimit.begin_response_capture(ctx, max_body_bytes)
  ctx.response_chunks = {}
  ctx.response_bytes = 0
  ctx.response_failed = false
  ctx.max_body_bytes = max_body_bytes
end

function SizeLimit.capture_response_chunk(ctx, chunk)
  if not chunk or #chunk == 0 then
    return
  end

  ctx.response_bytes = ctx.response_bytes + #chunk
  if ctx.response_bytes > ctx.max_body_bytes then
    if not ctx.response_failed then
      kong.log.err("Upstream response exceeds the crypto plugin size limit: buffered bytes=",
        ctx.response_bytes, ", limit=", ctx.max_body_bytes)
    end
    ctx.response_chunks = nil
    ctx.response_failed = true
    return
  end

  if not ctx.response_failed then
    ctx.response_chunks[#ctx.response_chunks + 1] = chunk
  end
end

function SizeLimit.finish_response_capture(ctx)
  if ctx.response_failed then
    return nil
  end

  local plaintext = table.concat(ctx.response_chunks)
  ctx.response_chunks = nil
  return plaintext
end

return SizeLimit

