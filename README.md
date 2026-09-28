# EncryptPii - 个人敏感信息应用层混合加密框架

本项目是一套针对敏感数据（PII，如手机号、身份证等）在客户端与服务端之间安全传输的**应用层混合加密方案**。基于 **RSA-2048 (OAEP) + AES-256 (GCM)**，通过“一次一密”的会话密钥机制，在 HTTPS/TLS 传输层之上提供纵深防御，有效防御中间人攻击、网络嗅探及数据篡改。

---

## 核心设计理念

1. **绝对禁止硬编码**：禁止在客户端硬编码对称密钥，禁止明文下发或明文传输对称密钥。
2. **一次一密（One-Time Session Key）**：客户端每次请求随机生成高强度 AES-256 会话密钥及 12 字节随机 IV。
3. **非对称密钥封装（KEM）**：使用服务端 RSA 公钥（OAEP 填充模式）加密 AES 会话密钥，随密文或 Header 安全传输给服务端。
4. **认证加密（AEAD）**：业务数据采用 AES-256-GCM 加密，自带 128 位认证标签（Tag），防窃听与防篡改。
5. **无侵入设计**：服务端采用 Spring MVC `RequestBodyAdvice` 与 `ResponseBodyAdvice` 机制，业务代码无需手动处理加解密。

---

## 模块结构

```text
EncryptPii/
├── common/       # 基础公共模块：核心加解密算法实现、数据传输载荷模型及工具类
│   ├── crypto/   # AesGcmCryptoService, SessionKeyService, CryptoSessionMaterialFactory
│   ├── model/    # 传输协议载荷 (payload: CipherRequestPayload, CipherResponsePayload, SessionKeyTransport) 与演示模型 (demo)
│   ├── constant/ # 核心算法常量 CryptoConstants
│   └── util/     # Base64 编码工具 EncodingUtils
├── server/       # 服务端模块 (Spring Boot, Port: 9090)
│   ├── advice/   # @DecryptRequest, @EncryptResponse 注解及全局切面处理器
│   ├── api/      # CryptoServerController (服务端加解密示例接口)
│   ├── codec/    # CryptoPayloadHandler (报文解析、上下文构建与加解密)
│   ├── context/  # CryptoSessionContext & CryptoSessionContextAccessor (请求级上下文传递)
│   └── service/  # CryptoServer (RSA 密钥管理与会话解密)
└── client/       # 客户端模块 (Spring Boot, Port: 8080)
    ├── api/      # CryptoClientController (调用演示接口)
    ├── core/     # CryptoClient (纯密码学加解密引擎), CryptoHttpClient (专职网络通信与公钥缓存)
    └── context/  # CryptoRequestContext (客户端本地会话解密上下文)
```

---

## 密码学选型规范

| 类别 | 算法 / 规范 | 参数与说明 |
|---|---|---|
| **非对称算法** | RSA | 2048 位密钥对，PKCS#8 私钥 / X.509 公钥格式 |
| **RSA 填充模式** | `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` | 抗选择密文攻击（IND-CCA2），禁止弱填充（如 PKCS1Padding） |
| **对称算法** | `AES/GCM/NoPadding` | 256 位密钥，带认证的 AEAD 模式 |
| **随机向量 (IV)** | 12 字节 (96-bit) | 每次加密使用 `SecureRandom` 独立生成，严禁复用 |
| **认证标签** | 128 位 (16 字节) | GCM 完整性校验标签，密文遭篡改时直接校验失败 |

---

## 交互流程与通信规范

### 1. 架构总览流程

```
┌─────────────┐                                  ┌─────────────┐
│   客户端     │                                  │   服务端     │
│             │          1. 获取服务端公钥         │             │
│             │◄─────────────────────────────────│  公钥(RSA)   │
│             │                                  │             │
│  2. 随机生成 AES 密钥及 IV                       │             │
│  3. RSA 公钥加密 AES 密钥                        │             │
│  4. AES-GCM 加密业务明文                         │             │
│             │   5. 发送密文 + 加密后AES密钥 + IV  │             │
│             │─────────────────────────────────►│             │
│             │                                  │ 6. RSA私钥解密出 AES 密钥 │
│             │                                  │ 7. AES-GCM 解密业务明文 │
│             │                                  │ 8. 处理业务并加密响应  │
│             │◄─────────────────────────────────│             │
└─────────────┘                                  └─────────────┘
```

### 2. 通信场景与传输字段速查表

网络上传输的核心字段按“请求/响应”维度总结如下：

| 方向 | 场景 | 传输位置 | 核心传输字段 | 说明 |
|---|---|---|---|---|
| **Server -> Client** | RSA 公钥获取 | 响应体 `PublicKeyResponse` | `publicKeyBase64`<br/>`keyId`<br/>`expiresAtEpochMillis` | 客户端启动或缓存失效时拉取，动态获取最新 RSA 公钥及轮换标识 |
| **Client -> Server** | RSA 双向加密<br/>(Bidirectional) | 请求体 `CipherRequestPayload` | `keyId` (可选)<br/>`encryptedSessionKeyBase64`<br/>`ivBase64`<br/>`encryptedDataBase64` | 客户端生成单次 AES 密钥并封装，随业务密文及使用的 keyId 一同上传 |
| **Server -> Client** | RSA 双向加密<br/>(Bidirectional) | 响应体 `CipherResponsePayload` | `ivBase64`<br/>`encryptedDataBase64` | 服务端复用该请求已解密的 AES 密钥，配合全新 IV 加密响应内容 |
| **Client -> Server** | RSA 仅请求加密<br/>(Request-Only) | 请求体 `CipherRequestPayload` | `keyId` (可选)<br/>`encryptedSessionKeyBase64`<br/>`ivBase64`<br/>`encryptedDataBase64` | 敏感入参加密上报，服务端精准/多版本回退解密后执行业务逻辑 |
| **Server -> Client** | RSA 仅请求加密<br/>(Request-Only) | 响应体 `PlainData` | `data` | 服务端直接返回明文业务响应体 |
| **Client -> Server** | RSA 仅响应加密<br/>(Response-Only) | 请求头 (Header)<br/>请求体 (Body) | Header: `X-Crypto-Session-Key`<br/>Header: `X-Crypto-Key-Id` (可选)<br/>Body: `PlainData` (`data`) | 请求入参明文，客户端将 RSA 公钥加密后的 AES 密钥置于 Header 中 |
| **Server -> Client** | RSA 仅响应加密<br/>(Response-Only) | 响应体 `CipherResponsePayload` | `ivBase64`<br/>`encryptedDataBase64` | 服务端解密 Header 获取 AES 密钥，对敏感出参进行加密传输 |

### 3. 核心传输字段说明

- **`publicKeyBase64`**：服务端导出的 RSA 公钥 X.509 编码 Base64 字符串。
- **`keyId`**：服务端密钥版本标识（如 `in-memory-test-key`），客户端请求可携带该值，服务端据此精准定位解密私钥，支持平滑轮换过渡。
- **`expiresAtEpochMillis`**：公钥有效截止时间戳（毫秒），驱动客户端本地缓存更新与定期拉取。
- **`encryptedSessionKeyBase64`**：客户端随机生成的 AES-256 会话密钥，经服务端 RSA 公钥（OAEP 填充模式）加密封装后的 Base64 字符串。
- **`ivBase64`**：AES-GCM 使用的 12 字节随机初始化向量（IV）Base64 字符串，严禁复用。
- **`encryptedDataBase64`**：业务明文使用 AES 会话密钥和对应 IV 加密后的 Base64 字符串（含 128 位 GCM 认证标签 Tag）。

### 4. 密钥平滑轮换（Key Rotation）机制

- **主动按期轮换**：服务端密钥默认以年为周期生成全新 `keyId` 与密钥对，并将新密钥标记为当前唯一活跃的下发密钥（Active Key）。
- **多版本密钥环（KeyRing）**：历史私钥持久化保留在服务端的密钥环中，过渡期（Grace Period）内仍可解密由旧密钥加密的数据。
- **精准路由与全量容错回退**：
  1. 客户端请求携带 `keyId` 时，服务端 O(1) 快速定位对应私钥解密；
  2. 若客户端未携带 `keyId` 或使用了过渡期旧公钥，服务端会先用活跃密钥尝试，失败后自动回退遍历密钥环中的历史过渡密钥，确保旧客户端请求零报错、平滑无感知升级。

### 4. 关键本地字段与安全边界（严禁明文传输）

- **`sessionKey` 明文**：客户端与服务端的 AES 对称密钥明文绝对禁止在网络中直接传输；在网络传输边界上，始终以 **RSA 公钥加密后的密文**（即 `encryptedSessionKeyBase64`）形式安全流转。
- **`CryptoRequestContext`**：仅存于客户端内存，用于在请求阶段保存生成的会话密钥与 IV，以便在收到服务端响应后进行局部对称解密。
- **`CryptoSessionContext`**：仅存于服务端线程/请求作用域（`ThreadLocal` / `RequestAttributes`），在拦截到加密请求时暂存解密后的会话密钥，并在响应切面加密完成后自动清理，实现请求隔离与用后即焚。

---

## 服务端注解无侵入使用

服务端开发仅需在 Controller 方法上标注注解，框架切面自动完成加解密及反序列化：

```java
@RestController
@RequestMapping("/api/user")
public class UserController {

    // 1. 双向加密接口
    @PostMapping("/update-phone")
    @DecryptRequest
    @EncryptResponse
    public UserProfileResponse updatePhone(@Valid @RequestBody UpdatePhoneRequest request) {
        // 入参已自动解密为明文对象；返回值将自动加密为 AesCipherPayload
        return userService.update(request);
    }

    // 2. 仅请求加密接口
    @PostMapping("/submit-idcard")
    @DecryptRequest
    public PlainResult submitIdCard(@Valid @RequestBody IdCardRequest request) {
        return userService.save(request);
    }

    // 3. 仅响应加密接口
    @PostMapping("/get-secret-profile")
    @EncryptResponse
    public UserProfileResponse getSecretProfile(
            @RequestBody PlainQuery query,
            @RequestHeader(CryptoConstants.HEADER_ENCRYPTED_SESSION_KEY) String sessionKeyBase64) {
        // 请求头中解析会话密钥并缓存到上下文，返回对象自动使用该会话密钥加密
        SessionKeyTransport transport = new SessionKeyTransport(sessionKeyBase64);
        CryptoSessionContextAccessor.setCryptoSessionContext(CryptoSessionContext.rsaResponseOnly(transport));
        return userService.getProfile(query);
    }
}
```

---

## 快速上手与运行

### 1. 环境准备
- JDK 17 或 JDK 21+
- Gradle (建议使用项目内置 `./gradlew`)

### 2. 构建与运行测试
```bash
./gradlew test
```

### 3. 启动服务端与客户端
```bash
# 启动服务端 (Port 9090)
./gradlew server:bootRun

# 新开终端启动客户端 (Port 8080)
./gradlew client:bootRun
```

### 4. 验证接口调用

客户端提供了一组测试端点，发起请求后会自动获取服务端公钥、执行客户端加密、请求服务端接口、接收密文并解密：

#### 场景 1：双向加解密（Bidirectional）
```bash
curl -X POST http://localhost:8080/crypto/client/bidirectional \
  -H "Content-Type: application/json" \
  -d '{"data":"13800138000"}'
```
**响应示例：**
```json
{
  "request": {
    "data": "13800138000",
    "encrypted": {
      "encryptedSessionKeyBase64": "...",
      "ivBase64": "...",
      "encryptedDataBase64": "..."
    }
  },
  "response": {
    "data": "mock rsa response for request - 13800138000",
    "encrypted": {
      "ivBase64": "...",
      "encryptedDataBase64": "..."
    }
  }
}
```

#### 场景 2：仅请求加密（Request-Only）
```bash
curl -X POST http://localhost:8080/crypto/client/request-only \
  -H "Content-Type: application/json" \
  -d '{"data":"13800138000"}'
```

#### 场景 3：仅响应加密（Response-Only）
```bash
curl -X POST http://localhost:8080/crypto/client/response-only \
  -H "Content-Type: application/json" \
  -d '{"data":"user-id-10001"}'
```

#### 直接调用服务端公钥接口
```bash
curl -X GET http://localhost:9090/crypto/server/public-key
```

---

## 常见安全误区与最佳实践

| 常见误区 | 潜在安全风险 | 解决方案 |
|---|---|---|
| 对称密钥硬编码在 App 包中 | 反编译 APK/IPA 即可直接提取密钥，安全机制形同虚设 | 强制一次一密，会话密钥每次请求随机生成 |
| 对称密钥通过明文接口下发 | 抓包工具或中间人即可直接获取明文密钥 | 严禁明文传输，使用非对称 RSA 公钥加密封装 |
| 使用 Base64 或 URL 编码伪装加密 | 仅仅是可逆编码，不具备任何保密性，监管不认可 | 采用合规的 AES-256-GCM 强密码算法 |
| 所有请求复用同一个对称密钥 | 任意一次泄露会导致历史所有会话被解密 | 每次请求生成独立会话密钥（Key Isolation） |
| RSA 使用 PKCS#1 v1.5 填充 | 易遭受 Bleichenbacher 填充预言机攻击 | 统一采用 `OAEPWithSHA-256AndMGF1Padding` |
| 服务端私钥硬编码在源码中 | 代码泄露（如代码库权限扩散）导致私钥失窃 | 私钥放入环境变量/文件管理，生产环境建议对接 KMS / HSM |