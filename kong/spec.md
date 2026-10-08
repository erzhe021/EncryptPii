# Kong 插件处理机制

## 1. 响应加密规则

当请求使用了响应加密模式（`config.encrypt_response = true`）时，Kong 会对上游返回的业务响应进行加密处理，不受 HTTP 状态码影响。

- 这包括成功响应和上游异常响应
- 也就是说，`200`、`400`、`500` 等都可以在该模式下被加密返回
- 客户端需按 `X-STC-Encrypted: true` 识别并解密响应体

## 2. Kong 自身错误的明文规则

只有 Kong 插件自身生成的非 2xx 错误，才返回明文错误信息，不进行加密。

- 例如：`KEY_EXPIRED`、`INVALID_KEY`、缺少请求头、Vault 不可用等
- 这些响应必须带上 `X-STC-Encrypted: false`
- 客户端应直接按明文 JSON 处理，不尝试解密

## 3. 普通传输 / 仅请求加密

对于以下两种场景，Kong 不会对响应进行加密：

- 普通传输（plain）
- 仅请求加密（request-only）

这些场景下，响应始终保持明文返回。

## 4. 设计原则

- 明文/密文判断基于“响应来源”，而不是简单依赖 HTTP 状态码
- Kong 自身构造的错误必须可被客户端快速识别与处理
- 上游敏感错误信息可以继续走加密协议，避免直接暴露给客户端

## 5. 客户端兼容要求

- 若 `X-STC-Encrypted == true`，则尝试解密响应体
- 若 `X-STC-Encrypted == false`，则按明文 JSON 处理
- 若响应体本身是加密载体（如 `ivBase64` / `encryptedDataBase64`），客户端也应按加密响应处理
