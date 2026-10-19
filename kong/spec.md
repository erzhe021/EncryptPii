# Kong 插件处理机制

## 1. 响应加密规则

仅当 `config.crypto_enabled = true`、请求带有 `X-STC-Enabled: true`（值不区分大小写）
且路由配置了 `config.encrypt_response = true` 时，Kong 才对上游返回的业务响应进行加密处理，
不受 HTTP 状态码影响。该头缺失或值为 `false` 时，路由的请求/响应加密配置均被绕过；
重复头、空值、额外空白或其他值返回 HTTP 400。服务端能力默认关闭，关闭时声明加密被拒绝。

- 这包括成功响应和上游异常响应
- 也就是说，`200`、`400`、`500` 等都可以在该模式下被加密返回
- 客户端需按 `X-STC-Encrypted: true` 识别并解密响应体

## 2. Kong 自身错误的明文规则

只有 Kong 插件自身生成的非 2xx 错误，才返回明文错误信息，不进行加密。

- 例如：`KEY_EXPIRED`、`INVALID_KEY`、缺少请求头、Vault 不可用等
- 这些响应必须带上 `X-STC-Encrypted: false`
- 客户端应直接按明文 JSON 处理，不尝试解密

## 3. 普通传输 / 仅请求加密

对于以下场景，Kong 不会对响应进行加密：

- 普通传输（plain）
- 仅请求加密（request-only）
- 带有 `X-STC-Enabled: false` 或未提供该头的加密路由

这些场景下，响应始终保持明文返回。

## 4. 设计原则

- 明文/密文判断基于“响应来源”，而不是简单依赖 HTTP 状态码
- Kong 自身构造的错误必须可被客户端快速识别与处理
- 上游敏感错误信息可以继续走加密协议，避免直接暴露给客户端
- 请求进入上游前移除 `X-STC-Enabled`、`X-STC-Key-Id` 和 `X-STC-Session-Key`，并继续执行网关认证注入及上游路径改写

## 5. 客户端兼容要求

- `X-STC-Enabled` 缺失或为 `false` 表示明文绕过；不区分大小写的单个 `true` 才执行路由加密配置。其他值或重复头（包括相同值重复）返回 HTTP 400。
- 缺失/关闭加密时，若出现 `X-STC-Key-Id` 或 `X-STC-Session-Key`（包括空值），请求返回 HTTP 400。启用加密时，这两个密钥头必须成对提供。
- 公钥接口不要求 `X-STC-Enabled`；所有转发请求都会在上游前移除这三个 STC 请求头。
- 若 `X-STC-Encrypted == true`，则尝试解密响应体
- 若 `X-STC-Encrypted == false`，则按明文 JSON 处理
- 若响应体本身是加密载体（如 `ivBase64` / `encryptedDataBase64`），客户端也应按加密响应处理

## 6. SDK 一致性与 Kong 边界

- 请求解密支持 JSON 与 URL 编码表单，必须携带相应 Content-Type；协议字段只能各出现一次。
- 无加密方向的路由及公钥接口拒绝 `X-STC-Enabled: true`。
- 密钥读取失败返回 HTTP 500；普通错误使用 SDK 的五字段错误结构，密钥错误使用 `code/msg/data`。
- RSA 使用 OAEP-SHA-256/MGF1-SHA-1；AES-GCM 接受 16/24/32 字节密钥，推荐客户端使用 32 字节。
- 会话密钥先尝试指定版本，再尝试当前及宽限期内历史版本，耗尽后才判定 `KEY_EXPIRED`。
- Kong 不自动生成或轮换密钥，不支持内存密钥；自动感知 Vault 新版本不等于自动轮换。
