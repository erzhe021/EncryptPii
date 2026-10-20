# Server SDK 集成示例

## 加解密与 Vault 开关

配置名为 `sensitive.transport.crypto.enabled`（不是 `enable`），默认关闭。
本示例将 `spring.cloud.vault.enabled` 关联到该开关。设置
`sensitive.transport.crypto.enabled=false` 后，不初始化 Spring Cloud Vault，
不加载、生成或轮换 SDK 管理的 Vault 密钥，不注册 SDK 加解密 Advice 或公钥接口；
业务 Controller 继续按明文处理，但显式声明加密的请求会被拒绝。
开启后仍按原配置加载 Vault 密钥，失败不会回退到明文模式。

```bash
./gradlew :server-with-sdk:bootRun --args='--sensitive.transport.crypto.enabled=false'
```

该开关在启动时生效，修改后需重启。`memory` 演示 profile 显式开启加密能力。
服务端开启时，`X-STC-Enabled` 缺失或为 `false` 仍走明文；只有 `true` 才按
`@DecryptRequest`、`@EncryptResponse` 执行对应方向。Header 非法或重复、
未启用却携带密钥头、启用时缺少密钥头、无注解接口声明启用，均返回 HTTP 400。
老加密客户端必须补上 `X-STC-Enabled: true`，不能再仅发送密钥头。
客户端开关不需要与服务端同时切换，但服务端必须先开启才能接受加密请求；
Header 不负责远程控制客户端开关。
如果应用还使用 Vault 管理其他配置或秘密，不应联动关闭整个 Spring Cloud Vault，
而应保留其独立配置；SDK 自身仍会在加解密关闭时跳过密钥初始化。
