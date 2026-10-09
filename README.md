# EncryptPii

EncryptPii 是基于 Spring Boot 的敏感数据传输加密示例项目，提供可复用的 Spring SDK，以及用于演示端到端加解密流程的 Java 服务端和微信小程序。

加密方案采用 RSA-2048 传输每次请求新生成的 AES-256 会话密钥，并使用 AES-GCM 加密请求或响应载荷。SDK 可集成 HashiCorp Vault KV v2，管理密钥存储、版本和轮换。

## 项目结构

```text
EncryptPii/
├── sdk/                                  # Spring Boot 加密 SDK
│   └── src/main/java/com/ikea/crypto/stc/
│       ├── annotation/                   # @DecryptRequest、@EncryptResponse
│       ├── config/                       # 自动配置与配置属性
│       ├── crypto/                       # AES 与会话密钥处理
│       ├── exception/                    # 加密异常类型
│       ├── key/                          # 密钥环、密钥服务与轮换协调
│       ├── model/                        # 协议和载荷模型
│       ├── session/                      # 请求级加密上下文
│       ├── vault/                        # Vault 集成
│       └── web/                          # MVC advice、编解码和公钥接口
├── server/                               # Java 演示服务端
│   └── src/main/
│       ├── java/com/ikea/crypto/server/
│       └── resources/application.yml
├── wechat/                               # 微信小程序演示及客户端 SDK
├── vault/vault.md                        # Vault 密钥生命周期与轮换设计
├── build.gradle
├── settings.gradle
└── gradlew
```

Gradle 当前包含 `sdk` 和 `server` 两个模块。微信小程序位于独立的 `wechat/` 目录，不是 Gradle 子模块。

## 加密设计

1. 服务端通过公钥接口提供 RSA 公钥和对应的 `keyId`。
2. 客户端为每个请求生成新的 AES-256 会话密钥和 AES-GCM IV。
3. 客户端使用服务端 RSA 公钥加密会话密钥，通过 `X-STC-Session-Key` 请求头发送；`keyId` 通过 `X-STC-Key-Id` 发送。
4. 客户端使用 AES-GCM 加密请求体。加密后的 JSON 请求体只包含 `ivBase64` 和 `encryptedDataBase64`。
5. 服务端 SDK 根据 `@DecryptRequest` 自动解密请求，并将会话上下文关联到当前请求。
6. 标注 `@EncryptResponse` 的接口使用该请求会话密钥加密响应。

支持以下接口模式：

- **双向加密**：请求和响应均加密。
- **仅加密请求**：请求体加密，响应明文返回。
- **仅加密响应**：请求可为明文，客户端仍需通过加密请求头提供会话密钥材料，以便服务端加密响应。

密钥版本过期时，SDK 返回 `KEY_EXPIRED` 错误及可用于更新的公钥信息。客户端应获取新公钥并使用新会话材料重试；不要对其他错误盲目重放请求。

SDK 自动配置 `CryptoExceptionHandler`，负责加密协议异常及对应 HTTP 响应。应用仍应在自己的异常处理器中处理业务异常和通用异常。SDK 不以 `GeneralSecurityException` 作为全局加密错误类型；应用边界应由 SDK 将相关底层错误转换为语义明确的加密异常。

加密异常响应会设置 `X-STC-Encrypted: false`，确保异常响应以明文返回。响应加密策略和应用级异常响应格式应结合接口行为进行配置与验证。

## 演示接口

公钥接口和加密演示接口默认使用 `/crypto/server` 前缀：

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/crypto/server/public-key` | 获取默认密钥别名的当前公钥 |
| `GET` | `/crypto/server/public-key/{keyAlias}` | 获取指定密钥别名的公钥 |
| `POST` | `/crypto/server/bidirectional` | 双向加密 |
| `POST` | `/crypto/server/request-only` | 仅加密请求 |
| `POST` | `/crypto/server/response-only` | 仅加密响应 |
| `POST` | `/crypto/server/response-only/client-exception` | 演示加密客户端异常 |
| `POST` | `/crypto/server/response-only/system-exception` | 演示系统异常 |
| `POST` | `/crypto/server/response-only/business-exception` | 演示业务异常 |
| `POST` | `/plain/server/normal` | 普通明文传输 |

服务端默认监听 `9090` 端口。微信小程序的接口映射和运行说明见 [`wechat/README.md`](wechat/README.md)。

## 引入 SDK

本地开发时，服务端通过 Gradle 项目依赖引用 SDK：

```groovy
implementation project(':sdk')
```

SDK 发布坐标为：

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

当前构建脚本将制品发布到本机 Maven Local 仓库。外部团队接入时，应将制品发布到组织认可的私有仓库，并使用已发布的正式版本。

## 配置示例

以下配置取自演示服务端，适用于本地开发；生产环境应使用 HTTPS，并通过部署平台或密钥管理系统注入 Vault 凭证。

```yaml
server:
  port: 9090

sensitive:
  transport:
    crypto:
      enabled: true
      auto-rotate: true
      endpoint:
        enabled: true
        base-path: /crypto/server
      key-lifecycle:
        validity-millis: 60000
        grace-period-millis: 10000
        rotation-before-expiry-millis: 20000
      vault:
        enabled: true
        addr: ${VAULT_ADDR:http://127.0.0.1:8200}
        auth-method: ${VAULT_AUTH_METHOD:TOKEN}
        auth-path: ${VAULT_AUTH_PATH:auth/kubernetes}
        token: ${VAULT_TOKEN:root}
        auto-bootstrap: true
        secret-path: ${VAULT_SECRET_PATH:secret/data/sensitive-transport-crypto/rsa-ciam}
        key-alias: ${VAULT_KEY_ALIAS:rsa-ciam}
        kubernetes:
          role: ${VAULT_K8S_ROLE:crypto-server}
          token-path: ${VAULT_K8S_TOKEN_PATH:/var/run/secrets/kubernetes.io/serviceaccount/token}
```

演示配置的默认 Vault 地址和 Token 仅用于本地开发，不可直接用于生产。生产部署应配置安全的 HTTPS 地址、认证方式、凭证和按服务隔离的密钥路径。

主要配置项：

- `sensitive.transport.crypto.enabled`：是否启用加密功能。
- `sensitive.transport.crypto.auto-rotate`：是否在访问公钥接口时自动轮换。
- `sensitive.transport.crypto.endpoint.enabled`：是否暴露公钥接口。
- `sensitive.transport.crypto.key-lifecycle`：密钥有效期、宽限期和提前轮换窗口。
- `sensitive.transport.crypto.vault.enabled`：是否使用 Vault 管理密钥。
- `sensitive.transport.crypto.vault.auto-bootstrap`：Vault 中没有密钥时是否自动创建初始密钥。
- `sensitive.transport.crypto.vault.key-alias` 和 `secret-path`：密钥别名与 Vault 密钥路径。

密钥生命周期参数需满足：

```text
grace-period-millis < rotation-before-expiry-millis < validity-millis
```

更多 Vault 生命周期、宽限期及多 Pod 轮换细节见 [`vault/vault.md`](vault/vault.md)。

## 本地运行

### 环境要求

- JDK 17 或更高版本
- 仓库自带的 Gradle Wrapper
- 若使用 Vault 模式，需提供可访问的 Vault KV v2 服务

运行测试：

```bash
./gradlew test
```

启动 Java 演示服务端：

```bash
./gradlew :server:bootRun
```

服务端默认启用 Vault 集成，因此本地运行前请确保 Vault 地址、认证信息和 KV v2 配置可用。Vault 集成测试在本地 Vault 不可用时会跳过。

## 安全与运维提示

- 每个服务或团队应使用独立的密钥别名、Vault 路径和访问策略，遵循最小权限原则。
- 启用 Vault 模式时，私钥材料存储在 Vault，并在服务运行期间加载到 JVM 内存；未启用 Vault 时 SDK 可使用内存密钥。不要将密钥材料写入代码仓库或客户端。
- 默认公钥接口只用于获取公钥；不要向未授权调用方暴露密钥轮换管理能力。
- 密钥轮换由服务端生命周期逻辑和 Vault CAS 协调；缓存命中时请求加解密在本地完成，启动加载、轮换及缓存未命中可能访问 Vault。
- 对生产流量使用 HTTPS；不要将真实个人信息发送到未受信任的服务。
- 具体安全边界和多团队接入建议见 [`vault/vault.md`](vault/vault.md)。

## 相关文档

- [`vault/vault.md`](vault/vault.md)：Vault 密钥生命周期、轮换与多团队接入最佳实践
- [`wechat/README.md`](wechat/README.md)：微信小程序演示的配置与运行说明
