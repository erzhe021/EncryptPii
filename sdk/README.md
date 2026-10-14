# 敏感传输加密 SDK 快速上手

本 SDK 为 Spring Boot Servlet 应用提供 HTTP 请求解密、响应加密、公钥接口和 Vault KV v2 密钥管理。默认使用 Vault，本地开发可显式选择内存密钥模式；Vault 失败时不会自动回退。本文面向接入团队，介绍依赖配置、最小接入方式和生产部署注意事项。

本仓库中 Java SDK 仅由 `server-with-sdk` 使用；它不是 Java 客户端 SDK。原 `client` 模块已移除，微信客户端使用独立的 `wechat/sdk`。SDK 的会话状态仅存于当前 Servlet 请求，不提供无 Web 请求的 ThreadLocal 回退；核心密钥解密不依赖 HTTP 请求上下文。

## 1. 环境要求

- JDK 17 或更高版本
- Spring Boot 3.x Servlet Web 应用
- 生产环境建议使用 HashiCorp Vault KV v2 保存和轮换 RSA 密钥

## 2. 引入依赖

发布到团队 Maven 仓库后，在应用中添加依赖：

Gradle：

```groovy
implementation 'com.ikea.crypto:sensitive-transport-crypto-spring-boot-starter:1.0-SNAPSHOT'
```

Maven：

```xml
<dependency>
    <groupId>com.ikea.crypto</groupId>
    <artifactId>sensitive-transport-crypto-spring-boot-starter</artifactId>
    <version>1.0-SNAPSHOT</version>
</dependency>
```

在本仓库开发或验证尚未发布的版本时，可使用 Gradle 项目依赖：

```groovy
implementation project(':sdk')
```

本仓库可通过以下命令发布到本机 Maven Local 仓库：

```bash
./gradlew :sdk:publishToMavenLocal
```

发布制品前请将版本号和仓库地址配置为团队正式使用的值；不要将 `SNAPSHOT` 版本作为生产依赖。

## 3. 配置密钥管理

### 生产环境：使用 Vault

确保 Vault 已启用 KV v2，并为服务身份配置仅能访问本服务密钥路径的策略。示例配置：

以下生命周期数值是显式的生产配置示例，会覆盖 SDK 默认值；例如示例将宽限期设为 10 天，而 SDK 默认值是 1 天。未配置时实际默认值以本文“重要配置项”表格为准。

```yaml
sensitive:
  transport:
    crypto:
      enabled: true
      key-store: vault
      auto-rotate: true
      endpoint:
        enabled: true
        base-path: /crypto/server
      key-lifecycle:
        validity-millis: 31536000000
        rotation-before-expiry-millis: 2592000000
        grace-period-millis: 864000000
      vault:
        enabled: true
        secret-path: secret/data/crypto/my-service
        key-alias: my-service
        auto-bootstrap: false
spring:
  cloud:
    vault:
      uri: ${VAULT_ADDR}
      authentication: KUBERNETES
      kubernetes:
        role: my-service
        kubernetes-path: kubernetes
        service-account-token-file: /var/run/secrets/kubernetes.io/serviceaccount/token
```

示例生命周期参数满足以下约束：

```text
grace-period-millis < rotation-before-expiry-millis < validity-millis
```

生产环境应使用 HTTPS Vault 地址和受控的认证凭证；不要将 Vault Token 或其他秘密写入代码仓库。若启用 `auto-bootstrap`，应用会在 Vault 中没有密钥时尝试以 CAS=0 创建初始密钥。生产环境是否允许自动引导，应按密钥初始化和审批流程决定。

Vault 地址与认证由 Spring Cloud Vault 管理。静态 Token 认证可将 `spring.cloud.vault.authentication` 设为 `TOKEN`，并通过 `spring.cloud.vault.token` 从环境变量或密钥管理系统注入 Token。

升级时将原先 `sensitive.transport.crypto.vault` 下的 Vault 地址和认证配置迁移到 `spring.cloud.vault`；密钥路径、别名和自动引导仍由 SDK 自身配置管理。

### 本地开发：内存密钥

本地验证必须显式选择 `key-store=memory`，并关闭 Spring Cloud Vault，避免其初始化认证或访问 Vault：

```yaml
sensitive:
  transport:
    crypto:
      enabled: true
      key-store: memory
      memory:
        key-alias: in-memory-test-key
spring:
  cloud:
    vault:
      enabled: false
```

SDK 会在应用启动时生成内存 RSA 密钥并输出开发模式警告。alias 固定且可配置，`keyId` 仍为 `<alias>:<数字版本>`：初始版本使用随机正整数（小于 2^52），降低不同启动之间 keyId 碰撞的概率，后续轮换按版本递增。内存密钥不会持久化，重启后客户端必须重新获取公钥；固定 alias 不意味着旧密文仍可解密。此模式不适合生产、多实例或需要跨重启保留密钥的环境，也不会与 Kong/Vault 的密钥共享。

本仓库的 `server-with-sdk` 提供显式的 `memory` profile（alias 为 `demo-service`），可在没有 Vault 和 `VAULT_TOKEN` 的情况下启动：

```bash
./gradlew :server-with-sdk:bootRun --args='--spring.profiles.active=memory'
```

默认 `key-store=vault`。Vault 被关闭、路径或别名未配置、缺少 `VaultTemplate`、认证或密钥加载失败均会导致启动失败，不会进入内存模式。仅设置 `vault.enabled=false` 不再支持无 Vault 启动，旧的本地配置必须改为显式选择 `key-store=memory`。Vault 中没有密钥时仍遵循 `auto-bootstrap`：`true` 时在 Vault 中初始化，`false` 时启动失败。

单元测试也可通过测试配置显式提供 `CryptoServer` Bean，自动配置会退让；不需要加解密时可关闭 `sensitive.transport.crypto.enabled`，并按需关闭 Spring Cloud Vault。

SDK 配置统一绑定到 `SensitiveTransportCryptoProperties`；生命周期和 Vault 设置分别作为 `key-lifecycle`、`vault` 子配置。现有 YAML 配置前缀保持不变。

## 4. 标注需要加解密的接口

在 Controller 方法或整个 Controller 类上添加注解。每种注解可单独使用，也可组合使用：

```java
package com.example.api;

import com.ikea.crypto.stc.annotation.DecryptRequest;
import com.ikea.crypto.stc.annotation.EncryptResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/profile")
public class ProfileController {

    @PostMapping
    @DecryptRequest
    @EncryptResponse
    public ProfileResponse update(@RequestBody UpdateProfileRequest request) {
        return new ProfileResponse(request.name(), request.phone());
    }

    public record UpdateProfileRequest(String name, String phone) {}

    public record ProfileResponse(String name, String phone) {}
}
```

- `@DecryptRequest`：SDK 解密请求体，再将明文交给 Spring MVC 转换为 `@RequestBody` 参数。
- `@EncryptResponse`：SDK 使用本次请求关联的 AES 会话密钥加密 Controller 成功响应。
- 两个注解同时使用：双向加密。
- 仅使用 `@DecryptRequest`：请求加密，成功响应保持明文。
- 仅使用 `@EncryptResponse`：成功响应加密；客户端仍必须在请求头中提供密钥 ID 和 RSA 加密后的会话密钥。

标准 Controller 返回值及其 JSON 序列化由应用决定；SDK 不要求使用特定的业务响应包装类型。

## 5. 客户端协议

客户端先请求公钥接口：

```text
GET /sensitive-transport-crypto/public-key
```

可使用 `sensitive.transport.crypto.endpoint.base-path` 修改默认前缀。公钥响应包含 `publicKeyBase64`、`keyId`、`expiresAtEpochMillis` 和 `refreshAtEpochMillis`；客户端应在建议刷新时间前更新缓存的公钥。

加密请求使用以下请求头和 JSON 请求体：

```http
X-STC-Key-Id: my-service:1
X-STC-Session-Key: <RSA 加密后的 AES 会话密钥，Base64>
Content-Type: application/json
```

```json
{
  "ivBase64": "<AES-GCM IV，Base64>",
  "encryptedDataBase64": "<AES-GCM 密文及认证标签，Base64>"
}
```

请求体中不传输 `keyId` 或 `encryptedSessionKey`。协议算法为 RSA-2048 OAEP 和 AES-256-GCM。RSA-OAEP 使用 SHA-256 摘要，MGF1 使用 SHA-1；AES-GCM 使用 12 字节 IV 和 128 位认证标签。客户端还需与服务端使用兼容的 Base64 编码格式。每次请求应生成新的会话密钥和 IV。

仅加密响应的接口虽然请求体可以是明文，客户端仍需发送上述两个加密请求头，以便服务端解密会话密钥并加密响应。

会话密钥会在读取请求时解析验证，再进入 Controller；非法 Base64、无法解密或长度不合法的 AES 密钥返回明文加密协议错误，不执行业务逻辑。

## 6. 异常处理

SDK 自动注册 `CryptoExceptionHandler`，处理 SDK 加密协议异常，并按客户端错误或服务端错误返回 HTTP 4xx/5xx。`KeyExpiredException` 返回 `KEY_EXPIRED` 及最新公钥信息；加密错误响应会设置 `X-STC-Encrypted: false`，并在密钥过期响应中设置 `Cache-Control: no-store`。

请求缺少字段、JSON/Base64 格式错误、IV 长度不为 12 字节、密文缺少完整的 16 字节 GCM 标签或 AES 会话密钥长度非法，归为客户端错误（HTTP 400）。GCM 验证失败使用 `DataTamperedException`；RSA 密文与候选私钥不匹配时允许尝试其他可用密钥。内部会话 context 缺失或误用、算法/密钥初始化失败和解析器非 JSON 格式类 I/O 故障归为服务端错误（HTTP 500），响应使用通用文案，具体原因保留在异常链和服务端日志中，不会伪装成请求格式错误。

应用仍需自行处理业务异常、应用系统异常及其他通用异常。SDK 不会把任意 `GeneralSecurityException` 当成全局加密异常；加密流程中的底层错误应在 SDK 的 HTTP 边界转换为语义明确的加密异常。若应用要自定义加密异常响应，可提供自己的 `CryptoExceptionHandler` Bean 替代 SDK 默认实现。

客户端只应在收到 `KEY_EXPIRED` 后按协议获取新公钥、重新生成会话材料并按业务幂等性决定是否重试；不要对所有 4xx/5xx 自动重放请求。

## 7. 重要配置项

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `sensitive.transport.crypto.enabled` | `true` | 是否启用 SDK 自动配置 |
| `sensitive.transport.crypto.key-store` | `vault` | 密钥存储模式；`memory` 必须显式选择，仅用于开发测试 |
| `sensitive.transport.crypto.memory.key-alias` | `in-memory-test-key` | 内存模式的稳定 alias，与 Vault alias 独立 |
| `sensitive.transport.crypto.auto-rotate` | `true` | 是否自动轮换密钥 |
| `sensitive.transport.crypto.endpoint.enabled` | `true` | 是否暴露公钥接口 |
| `sensitive.transport.crypto.endpoint.base-path` | `/sensitive-transport-crypto` | 公钥接口基础路径，可通过应用配置自定义 |
| `sensitive.transport.crypto.key-lifecycle.validity-millis` | 365 天 | 密钥有效期 |
| `sensitive.transport.crypto.key-lifecycle.rotation-before-expiry-millis` | 30 天 | 到期前触发自动轮换的时间窗口 |
| `sensitive.transport.crypto.key-lifecycle.grace-period-millis` | 1 天 | 替换密钥激活后，旧密钥的解密宽限期 |
| `sensitive.transport.crypto.vault.enabled` | `true` | `key-store=vault` 时必须启用，关闭不会触发内存回退 |
| `sensitive.transport.crypto.vault.key-alias` | 无，Vault 模式必须配置 | 密钥别名；`keyId` 格式为 `<keyAlias>:<version>` |
| `sensitive.transport.crypto.vault.secret-path` | 无，Vault 模式必须配置 | Vault KV v2 密钥路径 |
| `sensitive.transport.crypto.vault.auto-bootstrap` | `true` | Vault 没有密钥时是否自动创建初始密钥 |

Vault 认证方式、CAS 重试参数和 Kubernetes 认证设置见 [`vault/vault.md`](../vault/vault.md)。

## 8. 启动前检查

1. 确认应用是 Spring Boot Servlet Web 应用，且 SDK 依赖版本已发布到应用可访问的 Maven 仓库。
2. 确认生产环境客户端通过 HTTPS 访问公钥接口和业务接口。
3. 确认 Vault 已启用 KV v2，路径、角色和访问策略匹配；首次启动前检查自动引导设置。
4. 确认密钥生命周期参数满足 `grace < rotation-before-expiry < validity`。
5. 验证请求头、加密请求体和客户端 RSA-OAEP/AES-GCM 实现与本协议一致。
6. 验证过期密钥响应、普通加密错误响应及应用业务异常分别符合预期。

## 相关文档

- [`../vault/vault.md`](../vault/vault.md)：Vault 密钥生命周期、多 Pod 同步和轮换设计
- [`../README.md`](../README.md)：项目结构和演示服务说明
- [`../wechat/README.md`](../wechat/README.md)：微信小程序客户端示例
