# 敏感传输加密 SDK 快速上手

本 SDK 为 Spring Boot Servlet 应用提供 HTTP 请求解密、响应加密、公钥接口和 Vault KV v2 密钥管理。**加密能力默认关闭，请求默认明文；显式启用后才根据接口注解执行加解密。** 启用后默认使用 Vault，本地开发可选择内存密钥；Vault 失败时不会自动回退。

SDK 的会话状态仅存于当前 Servlet 请求，不提供无 Web 请求的 ThreadLocal 回退；核心密钥解密不依赖 HTTP 请求上下文。

## 行为速览

三个配置分别承担不同职责，不需要客户端与服务端同时切换：

| 配置 | 职责 |
| --- | --- |
| 服务端 `sensitive.transport.crypto.enabled` | 是否加载加密组件和密钥，默认 `false`；启动时生效 |
| 请求头 `X-STC-Enabled` | 本次请求是否使用加密，缺失等同于 `false` |
| `@DecryptRequest` / `@EncryptResponse` | 本次启用后，分别控制请求解密和响应加密方向 |

| 服务端能力 | 请求声明 | 结果 |
| --- | --- | --- |
| 关闭 | 缺失或 `false` | 明文处理 |
| 关闭 | `true` | HTTP 400，不把密文交给业务接口 |
| 开启 | 缺失或 `false` | 明文处理，跳过加解密注解 |
| 开启 | `true` | 按注解处理；无加密注解的接口返回 HTTP 400 |

**注解不是强制加密策略。** 当前协议允许调用方选择明文，不提供接口强制加密或远程控制客户端开关的能力。应用层加密也不替代 HTTPS、身份认证和访问控制。

微信客户端接入见 [`../wechat/sdk/README.md`](../wechat/sdk/README.md)。

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
      key-lifecycle:
        validity-millis: 31536000000
        rotation-before-expiry-millis: 2592000000
        grace-period-millis: 864000000
      vault:
        secret-path: secret/data/crypto/demo-service
        key-alias: demo-service
        auto-bootstrap: true
spring:
  cloud:
    vault:
      enabled: ${sensitive.transport.crypto.enabled:false}
      uri: ${VAULT_ADDR}
      authentication: KUBERNETES
      kubernetes:
        role: demo-service
        kubernetes-path: kubernetes
        service-account-token-file: /var/run/secrets/kubernetes.io/serviceaccount/token
```

启用加密能力后，公钥接口默认开放。上例将 Spring Cloud Vault 与 SDK 开关联动，
适用于 Vault 仅服务于本 SDK 的应用；若还用于其他业务秘密，应保留其独立开关。
生产环境应按密钥管理流程决定是否自动轮换和自动引导。

示例生命周期参数满足以下约束：

```text
grace-period-millis < rotation-before-expiry-millis < validity-millis
```

生产环境应使用 HTTPS Vault 地址和受控的认证凭证；不要将 Vault Token 或其他秘密写入代码仓库。若启用 `auto-bootstrap`，应用会在 Vault 中没有密钥时尝试以 CAS=0 创建初始密钥。生产环境是否允许自动引导，应按密钥初始化和审批流程决定。

Vault 地址与认证由 Spring Cloud Vault 管理。静态 Token 认证可将 `spring.cloud.vault.authentication` 设为 `TOKEN`，并通过 `spring.cloud.vault.token` 从环境变量或密钥管理系统注入 Token。

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

SDK 会在应用启动时生成内存 RSA 密钥并输出开发模式警告。alias 固定且可配置，`keyId` 仍为 `<alias>:<数字版本>`：初始版本使用随机正整数（小于 2^52），降低不同启动之间 keyId 碰撞的概率，后续轮换按版本递增。内存密钥不会持久化，重启后客户端必须重新获取公钥；固定 alias 不意味着旧密文仍可解密。此模式不适合生产、多实例或需要跨重启保留密钥的环境，也不会与 Vault 的密钥共享。

默认 `key-store=vault`。启用加密能力后，Vault 被关闭、路径或别名未配置、缺少 `VaultTemplate`、认证或密钥加载失败均会导致启动失败，不会进入内存模式。无 Vault 的本地开发必须显式选择 `key-store=memory`。Vault 中没有密钥时由 `auto-bootstrap` 决定行为：`true` 时在 Vault 中初始化，`false` 时启动失败。

单元测试也可通过测试配置显式提供 `CryptoServer` Bean，自动配置会退让。

### 关闭加密能力

配置名是 `sensitive.transport.crypto.enabled`，不是 `enable`。设为 `false` 或不配置时，
SDK 不初始化密钥管理、不加载或轮换 Vault 密钥，也不注册加解密 Advice 和公钥接口；
协议声明校验及协议异常处理仍保留，拒绝声明加密或携带未声明密钥头的请求。

Spring Cloud Vault 是独立组件，关闭 SDK 不会自动关闭它。如果应用仅为本 SDK 使用
Vault，可使用以下联动配置，避免不需要加密时仍初始化 Vault 认证：

```yaml
sensitive:
  transport:
    crypto:
      enabled: false
spring:
  cloud:
    vault:
      enabled: ${sensitive.transport.crypto.enabled:false}
```

`server-with-sdk` 示例已使用联动配置。服务端开关修改后需重启，不支持运行时卸载组件。

SDK 配置统一绑定到 `SensitiveTransportCryptoProperties`；生命周期和 Vault 设置分别作为 `key-lifecycle`、`vault` 子配置。

## 4. 标注需要加解密的接口

在 Controller 方法或整个 Controller 类上添加注解。它们仅在服务端能力开启且
请求声明 `X-STC-Enabled: true` 时生效：

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

| 接口注解 | 请求处理 | 响应处理 | 微信 SDK `mode` |
| --- | --- | --- | --- |
| 两者都有 | 解密后交给 Spring MVC | 加密 | `bidirectional` |
| 仅 `@DecryptRequest` | 解密后交给 Spring MVC | 明文 | `request-only` |
| 仅 `@EncryptResponse` | 明文，先建立加密会话 | 加密 | `response-only` |
| 无注解 | 不支持声明加密 | 不支持声明加密 | `plain` |

响应单向加密也支持无 `@RequestBody` 的 GET 等接口。响应加密沿用本次请求的会话，
业务异常响应也按原接口方向处理，不通过 HTTP 状态码决定是否加密。

标准 Controller 返回值及其 JSON 序列化由应用决定；SDK 不要求使用特定的业务响应包装类型。

## 5. 客户端协议

### 请求声明与校验

`X-STC-Enabled` 值不区分大小写，但必须是单个 `true` 或 `false`；
空值、额外空白、`1`、重复 Header（即使值相同）和逗号合并值均返回 HTTP 400。
以下情况也返回明文协议错误，且不会降级或继续执行业务逻辑：

- Header 缺失或为 `false`，却携带任意 `X-STC-Key-Id` / `X-STC-Session-Key`，包括空值。
- Header 为 `true`，但服务端能力关闭或接口无加密注解。
- Header 为 `true`，但密钥头缺失、重复、空白，或密钥/密文校验失败。

普通明文请求不需要获取公钥或发送密钥头。仅加密响应也必须发送
`X-STC-Enabled: true` 和两个密钥头，以便服务端建立响应会话。
Header 只声明是否启用，不携带方向；客户端必须事先与接口约定匹配的 `mode`。

### 公钥与密文格式

客户端仅在需要加密时请求公钥接口，无需为此 GET 声明启用或携带密钥头：

```text
GET /sensitive-transport-crypto/public-key
```

可使用 `sensitive.transport.crypto.endpoint.base-path` 修改默认前缀。公钥响应包含
`publicKeyBase64`、`keyId`、`expiresAtEpochMillis` 和 `refreshAtEpochMillis`；
客户端可缓存至建议刷新时间，并在下一次加密请求前刷新，无需后台定时器。
公钥接口可独立关闭；接口存在不代表客户端已自动启用加密。

`@DecryptRequest` 仅支持 `application/json` 请求体；其他或缺失的 `Content-Type` 会被拒绝。加密 JSON 请求使用以下请求头和请求体：

```http
X-STC-Enabled: true
X-STC-Key-Id: demo-service:1
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

会话密钥会在读取请求时解析验证，再进入 Controller；非法 Base64、无法解密或长度不合法的 AES 密钥返回明文加密协议错误，不执行业务逻辑。

响应加密时返回相同的密文载体，并设置 `X-STC-Encrypted: true`。
客户端应结合本次模式和响应标记解密，保留原 HTTP 状态；协议错误携带
`X-STC-Encrypted: false`，不可仅凭 4xx/5xx 判断响应是否加密。

## 6. 异常处理

SDK 自动注册 `CryptoExceptionHandler`，处理 SDK 加密协议异常，并按客户端错误或服务端错误返回 HTTP 4xx/5xx。`KeyExpiredException` 返回 `KEY_EXPIRED` 及最新公钥信息；加密错误响应会设置 `X-STC-Encrypted: false`，并在密钥过期响应中设置 `Cache-Control: no-store`。

请求缺少字段、JSON/Base64 格式错误、IV 长度不为 12 字节、密文缺少完整的 16 字节 GCM 标签或 AES 会话密钥长度非法，归为客户端错误（HTTP 400）。GCM 验证失败使用 `DataTamperedException`；RSA 密文与候选私钥不匹配时允许尝试其他可用密钥。内部会话 context 缺失或误用、算法/密钥初始化失败和解析器非 JSON 格式类 I/O 故障归为服务端错误（HTTP 500），响应使用通用文案，具体原因保留在异常链和服务端日志中，不会伪装成请求格式错误。

应用仍需自行处理业务异常、应用系统异常及其他通用异常。SDK 不会把任意 `GeneralSecurityException` 当成全局加密异常；加密流程中的底层错误应在 SDK 的 HTTP 边界转换为语义明确的加密异常。若应用要自定义加密异常响应，可提供自己的 `CryptoExceptionHandler` Bean 替代 SDK 默认实现。

客户端只应在收到 `KEY_EXPIRED` 后按协议获取新公钥、重新生成会话材料并按业务幂等性决定是否重试；不要对所有 4xx/5xx 自动重放请求。

## 7. 重要配置项

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `sensitive.transport.crypto.enabled` | `false` | 是否启用加密能力；协议声明校验始终启用 |
| `sensitive.transport.crypto.key-store` | `vault` | 密钥存储模式；`memory` 必须显式选择，仅用于开发测试 |
| `sensitive.transport.crypto.memory.key-alias` | `in-memory-test-key` | 内存模式的稳定 alias，与 Vault alias 独立 |
| `sensitive.transport.crypto.auto-rotate` | `true` | 是否自动轮换密钥 |
| `sensitive.transport.crypto.endpoint.enabled` | `true` | 加密能力开启时，是否暴露公钥接口 |
| `sensitive.transport.crypto.endpoint.base-path` | `/sensitive-transport-crypto` | 公钥接口基础路径，可通过应用配置自定义 |
| `sensitive.transport.crypto.key-lifecycle.validity-millis` | 31536000000 (365天) | 密钥有效期 |
| `sensitive.transport.crypto.key-lifecycle.rotation-before-expiry-millis` | 2592000000 (30天) | 到期前触发自动轮换的时间窗口 |
| `sensitive.transport.crypto.key-lifecycle.grace-period-millis` | 86400000 (1天) | 替换密钥激活后，旧密钥的解密宽限期 |
| `sensitive.transport.crypto.vault.key-alias` | 无，Vault 模式必须配置 | 密钥别名；`keyId` 格式为 `<keyAlias>:<version>` |
| `sensitive.transport.crypto.vault.secret-path` | 无，Vault 模式必须配置 | Vault KV v2 密钥路径 |
| `sensitive.transport.crypto.vault.auto-bootstrap` | `true` | Vault 没有密钥时是否自动创建初始密钥 |

Vault 部署、认证和手动轮换见 [`../vault/README.md`](../vault/README.md)；
SDK 的 CAS 参数见 `VaultProperties`，自动轮换由 SDK 自身的密钥管理流程负责。

## 8. 上线与迁移

旧加密客户端仅发送密钥头的方式不再兼容，必须补上 `X-STC-Enabled: true`。
升级服务端不会自动开启客户端开关，也不会为旧客户端推断启用状态。

1. 在测试环境验证新版客户端与服务端，再协调升级旧客户端；旧版仍在线时应保留隔离的旧协议入口。
2. 先部署并开启所有服务端实例的加密能力，再逐步开启新版客户端；期间服务端可同时接受明文与显式加密请求。
3. 客户端切换开关需创建新实例，已发出的请求由旧实例完成；不要求两端瞬时切换。
4. 关闭服务端能力前，先关闭客户端并等待旧实例、缓存和在途请求退出；提前关闭会明确拒绝仍在加密的请求。

当前没有远程策略接口，不提供“不发客户端版本即可远程切换”的自动能力。
接受明文也意味着迁移完成后不会自动变成强制加密。

## 9. 启动前检查

1. 确认应用是 Spring Boot Servlet Web 应用，且 SDK 依赖版本已发布到应用可访问的 Maven 仓库。
2. 确认生产环境客户端通过 HTTPS 访问公钥接口和业务接口。
3. 需要加密时显式开启服务端能力；Vault 模式确认 KV v2、路径、角色和访问策略匹配，并检查自动引导设置。
4. 确认密钥生命周期参数满足 `grace < rotation-before-expiry < validity`。
5. 确认客户端 `mode` 与注解一致，网关保留 `X-STC-Enabled` 和密钥头直到真正执行加解密的一层。
6. 验证 Header 缺失、显式明文、显式加密、非法声明、过期密钥及业务异常的响应。

## 相关文档

- [`../wechat/sdk/README.md`](../wechat/sdk/README.md)：客户端配置、模式、诊断和重试
- [`../server-with-sdk/README.md`](../server-with-sdk/README.md)：Spring 示例
- [`../kong/README.md`](../kong/README.md)：由 Kong 承担加解密时的部署与协议
- [`../vault/README.md`](../vault/README.md)：Vault 部署、认证和密钥轮换
