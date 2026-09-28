已在本项目中完成 **Vault 密钥同步与本地高性能加解密** 的完整实现，并通过了真实 Vault 实例与 Kubernetes Auth 的集成测试。

---

### 一、实现架构与时序

```text
Pod 启动阶段:
1. 读取 K8s SA Token (/var/run/secrets/kubernetes.io/serviceaccount/token)
2. 调用 Vault API: POST /v1/auth/kubernetes/login (携带 role + SA JWT)
3. 获取 Vault Client Token
4. 调用 KV v2 接口: GET /v1/secret/data/crypto/pii-transport-key
5. 将 RSA 密钥对加载至 JVM 内存的 KeyRing (私钥不落地)

业务请求阶段 (完全本地化，0 网络 RTT):
1. 客户端通过 GET /crypto/server/public-key 获取服务端公钥
2. 客户端加密生成 CipherRequestPayload
3. 服务端本地查找 KeyRing 内存私钥解密 SessionKey，AES-GCM 解密数据
```

---

### 二、核心改动组件

1. **`VaultProperties`** (`com.ikea.crypto.server.vault`):  
   配置 Vault 地址、认证方式（`KUBERNETES` 或 `TOKEN`）、K8s role、SA Token 路径及 KV 路径。
2. **`VaultClient`** (`com.ikea.crypto.server.vault`):  
   轻量级 HTTP 客户端（基于原生 `java.net.http.HttpClient`），实现 `loginWithKubernetes`、`readSecret`、`writeSecret`。
3. **`VaultKeySynchronizer`** (`com.ikea.crypto.server.vault`):  
   负责登录凭证换取、拉取/自动初始化 Vault 中的 RSA 密钥对，并反序列化注入内存 `KeyRing`。
4. **`KeyRing` & `CryptoConfiguration`**:  
   支持纯内存模式（`KeyRing.createInMemory()`），当 `crypto.vault.enabled=true` 时自动走 Vault 托管。
5. **`VaultIntegrationTest`**:  
   测试通过 `http://127.0.0.1:8200` 真实容器执行，涵盖 Token Auth、Kubernetes Auth 模拟、密文加解密全流程。

---

### 三、启用配置（`application.yml`）

```yaml
crypto:
  vault:
    enabled: true
    addr: http://vault.vault.svc:8200
    auth-method: KUBERNETES
    kubernetes:
      role: crypto-server
      token-path: /var/run/secrets/kubernetes.io/serviceaccount/token
    secret-path: secret/data/crypto/pii-transport-key
```






已将密钥生成、拉取、轮换及生命周期的核心逻辑**完全从本地磁盘文件迁移为 HashiCorp Vault 托管**：

---

### 一、核心改造方案

1. **`VaultKeyRing`（无文件依赖的密钥环）**：
    * **密钥获取**：启动时通过 Vault API（支持 K8s Auth 与 Token Auth）直接拉取 KV v2 中的当前活动密钥及宽限期内的历史密钥，加载至 JVM 内存。
    * **密钥生成（Auto-Bootstrap）**：若 Vault 中尚无密钥，自动生成 RSA-2048 密钥对并持久化写入 Vault KV，**绝不写入本地磁盘**。
    * **集群轮换（Rotate）**：调用 `rotateKey()` 时生成新版本密钥并更新 Vault，旧版本自动转为过渡期密钥；历史过期密钥从 Vault 与内存同步清除。
2. **`CryptoConfiguration`**：
    * 优先注入并初始化 `VaultKeyRing`；各 Pod 变为完全无状态，多 Pod 共享 Vault 中的同一组版本化密钥。
3. **配置升级（`application.yml`）**：
    * 默认启用 `crypto.vault.enabled: true`，支持通过环境变量动态切换 K8s Auth 或 Token Auth。

---

### 二、已通过测试验证

* **`VaultKeyRingTest`**：验证了 Vault 中初始密钥自动生成、多版本轮换写入、旧密钥宽限期解密回退、多 Pod 从 Vault 并发拉取的完整生命周期。
* **`VaultIntegrationTest`**：涵盖 Kubernetes SA Token 认证模拟与本地纳秒级解密。
* **全量单元与集成测试**：`./gradlew test` 100% 通过。