### 总结一下client-server之间的加密通信流程和传输字段。

---

**核心传输字段可以按“握手/请求/响应”来总结。** `CryptoRequestContext` 自身不上传；网络上传的是其中派生出的公钥、会话密钥封装、IV、密文等字段。

| 方向 | 场景 | 传输位置 | 核心字段 |
|---|---|---|---|
| Server -> Client | RSA 公钥获取 | 响应体 | `publicKey`（`RsaPublicKeyResponse`） |
| Server -> Client | ECDH 公钥获取 | 响应体 | `ephemeralPublicKeyBase64`，以及其签名/验签相关字段（`EcdhPublicKeyResponse`） |
| Client -> Server | RSA 双向/请求加密 | 请求体 `RsaCipherPayload` | `encryptedSessionKeyBase64`、`ivBase64`、`encryptedDataBase64` |
| Server -> Client | RSA 双向响应 | 响应体 `RsaCipherPayload` | `encryptedSessionKeyBase64`、`ivBase64`、`encryptedDataBase64` |
| Client -> Server | RSA 仅响应加密 | 请求头 | `X-Client-Session-Key`、`X-Client-Session-IV` |
| Server -> Client | RSA 仅响应加密 | 响应体 | `ivBase64`、`encryptedDataBase64` |
| Client -> Server | ECDH 双向/请求加密 | 请求体 `EcdhCipherPayload` | `clientEphemeralPublicKeyBase64`、`serverEphemeralPublicKeyBase64`、`ivBase64`、`encryptedDataBase64` |
| Server -> Client | ECDH 双向响应 | 响应体 `EcdhCipherPayload` | `clientEphemeralPublicKeyBase64`、`serverEphemeralPublicKeyBase64`、`ivBase64`、`encryptedDataBase64` |
| Client -> Server | ECDH 仅响应加密 | 请求体 `EcdhResponseOnlyRequest` | `data`、`clientEphemeralPublicKeyBase64`、`serverEphemeralPublicKeyBase64` |
| Server -> Client | ECDH 仅响应加密 | 响应体 | `ivBase64`、`encryptedDataBase64` |

**字段含义：**
- `encryptedSessionKeyBase64`：客户端生成的 AES 会话密钥，经服务端 RSA 公钥加密后的结果。
- `ivBase64`：AES-GCM 使用的随机 IV。
- `encryptedDataBase64`：业务明文加密后的密文。
- `clientEphemeralPublicKeyBase64` / `serverEphemeralPublicKeyBase64`：ECDH 协商用的临时公钥。

**不会上传的关键本地字段：**
- `sessionKey` 明文通常不直接传；但在 **RSA 仅响应加密** 场景中，会以“**RSA 加密后的 session key**”放进请求头 `X-Client-Session-Key`。
- `clientEphemeralPrivateKey` 不会上传。
- `CryptoRequestContext` 只是 client 本地保存这些解密上下文的容器。