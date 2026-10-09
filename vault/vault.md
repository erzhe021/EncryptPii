# HashiCorp Vault 密钥生命周期管理与分布式轮换设计

本项目使用 **HashiCorp Vault KV v2** 管理传输加密密钥，并通过本地内存密钥环（`VaultKeyRing`）支持多 Pod 密钥同步与轮换。常规请求在本地完成加解密，不访问 Vault；启动加载、轮换和缓存未命中时才访问 Vault。

> 说明：应用会按密钥生命周期配置自动轮换；`GET /crypto/server/public-key` 只用于获取公钥，不提供 HTTP 轮换接口。受控的运维入口可在应用内调用强制轮换能力。

---

## 一、架构设计与核心价值

```text
                                  +---------------------------------------+
                                  |         HashiCorp Vault KV v2         |
                                  |  - 权威多版本托管 (v1, v2, v3...)        |
                                  |  - Check-And-Set (CAS) 原子并发控制   |
                                  +-------------------+-------------------+
                                                      ^
                               [控制面: 启动/轮换/Cache Miss]
                                                      v
      +-----------------------------------------------+-----------------------------------------------+
      |                                               |                                               |
+-----+----------------------------------+     +-----+----------------------------------+     +-----+----------------------------------+
| Pod 1 (Crypto Server)                  |     | Pod 2 (Crypto Server)                  |     | Pod N (Crypto Server)                  |
|  - VaultKeyRing (JVM 内存)             |     |  - VaultKeyRing (JVM 内存)             |     |  - VaultKeyRing (JVM 内存)             |
|    * Active Key (v2) -> 提供公钥        |     |    * Active Key (v2) -> 提供公钥        |     |    * Active Key (v2) -> 提供公钥        |
|    * Transition Keys (v1) -> 宽限期解密  |     |    * Transition Keys (v1) -> 宽限期解密  |     |    * Transition Keys (v1) -> 宽限期解密  |
|  - 本地加解密引擎 (缓存命中时不访问 Vault) |     |  - 本地加解密引擎 (缓存命中时不访问 Vault) |     |  - 本地加解密引擎 (缓存命中时不访问 Vault) |
+----------------------------------------+     +----------------------------------------+     +----------------------------------------+
```

### 核心优势
1. **集中管理**：密钥材料持久化在 Vault KV v2，应用 Pod 将所需密钥加载到 JVM 内存；密钥不会由该流程写入 Pod 本地文件。
2. **本地请求处理**：命中本地密钥环时，请求加解密不依赖 Vault 的网络延迟；启动、轮换和缓存未命中仍需要 Vault 通信。
3. **平滑轮换**：新旧密钥在宽限期内共存，支持处理使用旧公钥生成的在途请求。
4. **并发协调**：Vault KV v2 CAS 和双重检查刷新减少多个 Pod 并发轮换造成的重复写入。
5. **按需同步**：Pod 缺少请求对应的密钥版本时，可从 Vault 拉取并缓存该版本。

---

## 二、密钥数据模型与版本规范

### 1. Key ID 命名规范
系统以 `<keyAlias>:<version>` 格式唯一标识一个密钥版本，例如：
* `rsa-ciam:1`
* `rsa-ciam:2`

客户端通过 `X-STC-Key-Id` 请求头携带 `keyId`，通过 `X-STC-Session-Key` 请求头携带 RSA 加密的会话密钥。加密请求体只包含 `ivBase64` 和 `encryptedDataBase64`，不再接受在请求体中传递密钥字段。

### 2. Vault KV v2 存储格式
在 Vault 的 Secret 路径（默认 `secret/data/sensitive-transport-crypto/rsa-ciam`）下存储：
```json
{
  "data": {
    "publicKey": "<Base64 X.509 编码公钥>",
    "privateKey": "<Base64 PKCS#8 编码私钥>"
  }
}
```
* **版本与时间戳**：直接复用 Vault 原生 Metadata 中的 `version` 和 `created_time`（ISO-8601）。
* **有效期计算**：`expiresAt = parse(created_time) + validityMillis`。无需人工写入冗余时间字段，保证权威一致性。

---

## 三、密钥生命周期全流程

```text
  [Bootstrap / 生成]
          │  (Auto-Bootstrap 生成 RSA 密钥对，CAS=0 写入 Vault)
          ▼
   [Active 活跃期]  ──────────────> 对外暴露公钥 (/crypto/server/public-key)
          │                         支持本地快速解密
          │ (达到有效时长 / 触发轮转)
          ▼
 [Transition 宽限期] ─────────────> 停止分发公钥；保留私钥在内存中
          │                         支持历史在途请求回退解密 (Grace Period)
          │ (超过 validity + gracePeriod)
          ▼
   [Purged 淘汰期]  ──────────────> 从 JVM 内存移除，拒绝该版本的解密请求
```

### 1. 自动引导（Auto-Bootstrap）
Pod 启动初始化时（`VaultKeyRing.initialize()`）：
1. 尝试从 Vault 读取最新版本密钥；
2. 若 Vault 路径不存在（404）且开启了 `sensitive.transport.crypto.vault.auto-bootstrap=true`，Pod 调用 `rotationCoordinator.bootstrapInitialKey()`；
3. 使用 `CAS=0` 原子写入初始密钥（v1），避免多个 Pod 冷启动时重复初始化。

### 2. 启动加载与多版本回溯（Startup Backtracking）
当 Vault 中已有密钥时，Pod 启动会自适应回溯加载历史版本：
1. **加载最新版本**：拉取最新版本作为当前的 `Active Key`；
2. **向前回溯（currentVersion - 1 到 1）**：
   * 依次加载历史密钥为 `Transition Key`（用于支持老密文解密）；
   * **短路机制（Early Termination）**：当检测到某一历史版本已超过宽限期（`isExpiredBeyondGrace` 为 true），立即终止向前扫描，避免无效网络请求。

### 3. 业务加解密阶段（Zero-RTT 本地解密）
1. 客户端通过 `GET /crypto/server/public-key` 获取当前 `Active Key` 的公钥与 `keyId`；
2. 客户端将 `keyId` 与加密后的 `sessionKey` 放入上述请求头，将 AES-GCM IV 与密文放入请求体；
3. 服务端优先在本地 `KeyRing` 查找私钥并执行解密。缓存命中时不访问 Vault；缓存未命中时会按需查询 Vault。

当请求携带的 key 版本已超过宽限期时，服务端返回 HTTP 400，错误码为 `KEY_EXPIRED`，并在 `data` 中提供最新公钥信息。客户端可安装该公钥并使用全新会话密钥重试一次；其他错误不应自动重放。

### 4. 缓存未命中按需补拉（Cache Miss On-Demand Fetching）
在多 Pod 部署环境中，若 Pod A 执行了轮转并生成了 v2，客户端使用 v2 加密向 Pod B 发起请求，而 Pod B 尚未执行同步：
1. Pod B 在本地 `KeyRing` 中未找到 `keyId`（Cache Miss）；
2. 自动触发 `fetchAndCacheFromVault(keyId)`；
3. 从 Vault 获取对应版本密钥，校验未超过宽限期后存入本地内存缓存；
4. 若该版本未过期且版本号大于当前 Active 版本，自动晋升为 Pod B 的 Active Key；
5. 正常解密密文，避免了因集群各节点缓存不一致导致的请求失败。

### 5. 过期淘汰（Purge）
在初始化与每次轮换后触发 `purgeExpiredKeys()`。达到 `retirementTime`（通常是替换密钥激活时间加宽限期）的非活跃密钥会从内存 `keyEntriesById` 移除；活跃密钥不会被清理。

---

## 四、多 Pod 分布式密钥轮换机制

为了解决多 Pod 环境下密钥轮换的脑裂、重复写入与流量断流问题，系统设计了 **Double-Checked Refresh + Vault KV v2 CAS + Backoff Retry** 协同机制。

```text
[触发轮换] -> [1. 双重检查 (Double-Checked Refresh)]
                     │
         Vault 是否已有未过期的新版本?
             ├── 是 ──> [直接同步 Vault 最新版本至本地内存] ──> [结束 (无需写 Vault)]
             └── 否 ──> [2. 尝试 CAS 条件写入 (Vault KV v2)]
                                   │
                           CAS 是否匹配 (成功)?
                               ├── 是 (写入成功的 Pod) ──> [写入 RSA 密钥对并激活本地密钥]
                               │                     [清理已过期的历史版本]
                               └── 否 (冲突 Pod) ──> [捕获 VaultCasMismatchException]
                                                     [3. 退避等待 (Backoff 1~2s)]
                                                     [4. 重试拉取获胜 Pod 写入的新版本并激活]
```

### 1. 双重检查刷新（Double-Checked Refresh）
在触发轮换操作时：
* 首先主动拉取 Vault 中最新的密钥元数据；
* 若发现 Vault 中的密钥版本大于本地当前版本且尚未过期，说明其他 Pod 刚刚已成功完成轮换，当前 Pod **直接将 Vault 最新密钥同步至本地内存**，终止本次生成与写入。
* 避免了 Pod 集群因定时任务或并发调用导致的版本频频暴增。

### 2. Vault KV v2 Check-And-Set (CAS) 并发控制
若双重检查确认需轮转，Pod 执行 CAS 写入：
* 设当前已知最新版本为 $N$；
* 调用 `writeSecret(path, data, cas=N)`（指定 Vault 校验前置版本）；
* **CAS 写入成功的 Pod**：Vault 分配递增版本 $N+1$，Pod 将该版本更新为本地 `Active Key`；
* **竞态失败的 Pod**：Vault 返回 CAS 冲突，客户端抛出 `VaultCasMismatchException`，随后进入退避与重试流程。

CAS 是版本条件写入，并非持有型分布式锁；只有一个 Pod 能以同一个旧版本号成功写入。

### 3. 退避等待与自动同步（Backoff & Fetch Latest）
竞态失败的 Pod 进入优雅容错处理：
1. **退避等待**：休眠 `casBackoffMillis`（默认 1200ms），等待成功写入的 Pod 完成密钥同步；
2. **重试轮询**：按照 `casRetryIntervalMillis` 最多重试 `casMaxRetries` 次向 Vault 查询最新版本；
3. **自动同步**：拉取到新版本密钥后反序列化注入本地 KeyRing 并激活。

### 4. 强制轮换（Force Rotate）
`CryptoServer.forceRotateKey(keyAlias)` 提供强制轮换能力，Vault 模式下仍由 SDK 通过 CAS 协调并更新本地密钥环。当前没有公开的 HTTP 轮换端点；运维工具如需触发轮换，应调用经过授权的应用内管理入口，而不是直接改写 Vault 中的密钥数据。

---

## 五、多团队接入最佳实践

当 SDK 分发给多个团队时，建议采用“**统一协议、独立密钥域**”模型。各服务共用经评审并统一升级的 SDK 和协议实现，但默认使用独立密钥材料。

### 1. 推荐原则

- 每个服务独立管理 `keyAlias`、Vault 密钥路径及密钥生命周期，避免一个服务的密钥泄露影响其他服务，也便于独立轮换和审计。
- Vault 按服务身份实施最小权限控制；服务运行身份默认只能访问自身的密钥路径，不授予跨服务读写权限。
- 本地、测试、预发布和生产环境分别配置 Vault 地址、认证凭证及密钥路径，不跨环境共用生产密钥。
- 不要将生产 Token 或其他秘密提交到代码仓库；通过部署环境或密钥管理系统注入凭证。

### 2. 推荐配置拆分

#### 共享部分

- 请求/响应加密协议及载荷结构
- 公钥获取接口和客户端刷新流程
- 经评审并统一升级的 SDK 版本

#### 独立部分

- `sensitive.transport.crypto.vault.key-alias`
- `sensitive.transport.crypto.vault.secret-path`
- Vault 地址、认证方式、角色及凭证
- 密钥有效期、轮换窗口、宽限期及 CAS 参数
- 按服务身份配置的 Vault 访问策略

### 3. Vault 路径示例

```text
secret/data/crypto/service-a
secret/data/crypto/service-b
secret/data/crypto/service-c
```

每个服务的运行身份只应有权访问自身路径；确需跨服务访问时，必须经过安全评审并记录授权范围。

### 4. 运维建议

- 按服务独立轮换密钥，并保留轮换操作的审计记录。
- 公钥获取接口可向客户端开放；私钥只由服务端管理，不向客户端或其他服务分发。
- 不要通过应用 HTTP 接口公开密钥轮换操作。需要人工或自动化触发时，应使用经过授权的运维流程，并记录操作人、目标服务和执行结果。
- 客户端收到密钥过期错误时，按协议获取新公钥后再重试；不要对其他错误盲目重放请求。

### 5. 何时可以共享密钥

仅当多个服务属于同一信任域、采用一致的安全控制，并被明确视为同一个安全边界时，才考虑共享密钥。应记录例外原因、涉及的服务、风险接受方和复核计划；默认仍应使用独立密钥。

---

## 六、核心实现组件

| 组件 | 类名 | 核心职责 |
| :--- | :--- | :--- |
| **密钥环管理** | `VaultKeyRing` | 继承自 `KeyRing`，负责本地内存密钥存储、启动回溯、Cache Miss 按需拉取与委托操作 |
| **轮换协调器** | `VaultRotationCoordinator` | 实现双重检查、Vault CAS 条件写入、退避等待与冲突重试拉取 |
| **数据访问层** | `VaultKeyRepository` | 负责与 Vault KV v2 交互，封装版本化读写、CAS 参数传递与路径解析 |
| **编解码转换** | `VaultKeyCodec` | 负责 RSA 密钥与 X.509/PKCS#8 Base64 的双向序列化、时间戳与版本解析 |
| **客户端通讯** | `VaultClient` | 基于 Spring Vault 的 KV v2 访问封装，支持 Kubernetes Auth 与 Token Auth |
| **身份认证器** | `VaultAuthenticator` | 支持 Kubernetes ServiceAccount Token 自动挂载登录与静态 Token 认证 |
| **配置属性** | `VaultProperties` | 统一配置项（地址、认证方式、路径、有效时长、宽限期、CAS 参数等） |

---

## 七、配置与运维接口

### 1. 配置参数说明（`application.yml`）

```yaml
sensitive:
  transport:
    crypto:
      key-lifecycle:
        # 密钥有效期 (毫秒，默认 365 天)
        validity-millis: 31536000000
        # 到期前主动轮换窗口 (毫秒，默认 30 天)
        rotation-before-expiry-millis: 2592000000
        # 宽限过渡期 (毫秒，默认 1 天)
        grace-period-millis: 86400000
      vault:
        # 是否开启 Vault 托管 (开启后自动使用 VaultKeyRing)
        enabled: true
        # Vault 服务地址
        # 生产环境应使用 HTTPS，并验证 Vault TLS 证书
        addr: https://vault.vault.svc:8200
        # 认证方式: KUBERNETES 或 TOKEN
        auth-method: KUBERNETES
        # auth-method 为 TOKEN 时通过环境变量或密钥管理系统注入；不要提交生产 Token
        token: ${VAULT_TOKEN:}
        # Vault KV v2 挂载与路径
        secret-path: secret/data/sensitive-transport-crypto/ciam
        # 逻辑密钥别名 (keyId 格式为 <keyAlias>:<version>)
        key-alias: ciam
        # 是否在 Vault 为空时自动初始化密钥
        auto-bootstrap: true
        # CAS 竞态失败时的退避等待时长 (毫秒，默认 1200ms)
        cas-backoff-millis: 1200
        # CAS 竞态失败后的最大轮询重试次数
        cas-max-retries: 3
        # 重试轮询间隔 (毫秒)
        cas-retry-interval-millis: 500
        kubernetes:
          # Vault 中配置的 Kubernetes 认证角色名
          role: crypto-server
          # K8s 容器挂载的 ServiceAccount Token 路径
          token-path: /var/run/secrets/kubernetes.io/serviceaccount/token
```

### 2. 获取当前服务端活跃公钥
* **请求**：`GET /crypto/server/public-key`
* **响应**：
```json
{
  "publicKeyBase64": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...",
  "keyId": "ciam:3",
  "expiresAtEpochMillis": 1760000000000,
  "refreshAtEpochMillis": 1757321600000
}
```
`refreshAtEpochMillis` 是建议客户端刷新公钥的时间；响应字段以 `PublicKeyResponse` 为准。

---

## 八、自动化测试与验证

项目包含针对 Vault 密钥生命周期的单元测试，以及一个在本地 Vault（`http://127.0.0.1:8200`）可用时运行的集成测试：

1. **`VaultMultiVersionGracePeriodTest`**：
   * 验证启动时多版本（v1/v2/v3）自动回溯加载；
   * 验证处于宽限期内的历史密钥（v2）解密能力依然有效；
   * 验证超出宽限期的废弃密钥（v1）被正确过滤丢弃并不予解密；
   * 验证短路机制（未请求版本 0）。
2. **`VaultKeyRingTest`**：
   * **生命周期端到端**：初始密钥自引导生成（v1）-> 业务加密 -> 轮换（v2）-> 老密钥宽限期解密 -> 新密钥正常加解密；
   * **多 Pod 自动同步**：Pod 1 轮转后，Pod 2 通过双重检查刷新同步最新版本；
   * **多 Pod 并发 CAS 冲突**：两 Pod 同时触发轮转，验证一个写入成功、另一个退避后拉取，Vault 版本平稳递增；
   * **失效时懒轮转刷新**：密钥自然过期后，Pod 触发双重检查刷新复用已由他方轮换的新版本；
   * **Cache-Miss 按需加载**：Pod 2 未感知 v2 时接收 v2 加密报文，触发按需拉取解密成功并自动升级活跃版本。
3. **`VaultIntegrationTest`**：
   * 验证本地 Vault 的 Token Auth 与端到端本地加解密；Vault 不可用时跳过。