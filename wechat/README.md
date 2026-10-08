# EncryptPii 微信小程序

此小程序提供普通传输、双向加密、请求加密和响应加密四种传输演示，以及响应加密的客户端异常、系统异常、业务异常三种请求。小程序默认直接连接 Java Server：从 Server 获取 RSA 公钥，在本机执行 RSA-OAEP-SHA-256（MGF1-SHA-1）和 AES-256-GCM 加解密，再按 STC 协议提交请求。

## 配置与运行

1. 修改 `config.js` 中的 `SERVER_BASE_URL`，设置为 Java Server 地址，默认是 `http://localhost:9090`；真机使用手机可访问的 HTTPS 域名。不要填写 Client 或 Kong Admin API 地址；`KEY_REFRESH_MARGIN_MS` 配置公钥到期前多少毫秒开始按需刷新，设为 `0` 表示到期才刷新。
2. 在微信开发者工具中导入 `wechat` 目录并运行。发布前请确认 `project.config.json` 中配置的是团队自己的小程序 AppID。
3. 在小程序管理后台将服务域名加入 `request` 合法域名；生产环境必须使用 HTTPS。

本地开发者工具可直接使用 `http://localhost:9090`，无需额外开关。
在开发者工具的本地设置中勾选“不校验合法域名、web-view（业务域名）、TLS 版本以及 HTTPS 证书”。
SDK 只允许 `localhost`、`127.0.0.1` 和 `[::1]` 的 HTTP 地址，不允许远程 HTTP。
真机的 `localhost` 指向手机自身；真机和生产环境应使用手机可访问的 HTTPS 地址。
服务仍须实现下表的接口和 STC 协议。

Java Server 默认允许直接访问，无需 `local` profile 或 gateway token：

```sh
./gradlew :server:bootRun
```

密钥管理仍使用 `server/src/main/resources/application.yml` 中的 Vault 配置。
如果 Server 已在运行，需要先停止旧实例，再重新启动以加载修改。

## 接口映射

| 小程序模式 | Server 路由 |
| --- | --- |
| 获取公钥 | `GET /crypto/server/public-key` |
| 普通传输 | `POST /plain/server/normal` |
| 双向加密 | `POST /crypto/server/bidirectional` |
| 请求加密 | `POST /crypto/server/request-only` |
| 响应加密 | `POST /crypto/server/response-only` |
| 客户端异常 | `POST /crypto/server/response-only/client-exception` |
| 系统异常 | `POST /crypto/server/response-only/system-exception` |
| 业务异常 | `POST /crypto/server/response-only/business-exception` |

三种异常请求均使用明文请求内容输入框和响应加密请求头。客户端异常返回 HTTP 400，系统异常返回 HTTP 500，业务异常返回 HTTP 200 和业务错误码；页面仍展示请求明文、请求密文、响应密文、响应明文和延迟，未使用的密文项显示 `N/A`。

双向、请求加密和响应加密模式均通过 `X-STC-Key-Id` 和 `X-STC-Session-Key` 请求头发送 keyId 与 RSA 加密的 AES 会话密钥；请求密文体只包含 `ivBase64` 和 `encryptedDataBase64`。旧版请求体密钥格式不再兼容。请求加密模式与 Java SDK 使用相同的 RSA OAEP 摘要参数、AES-GCM IV 和认证标签格式。公钥在内存中缓存至配置的提前刷新点；刷新由下一次加密请求触发，不运行后台定时器。收到 `KEY_EXPIRED` 时刷新并最多重试一次，重试会重新生成会话材料及请求头。

RSA/AES 实现使用 SDK 内置的 node-forge 浏览器 bundle，见 `sdk/lib/FORGE-LICENSE.txt`。会话密钥、IV 和 RSA OAEP seed 均按请求使用微信 `wx.getRandomValues` 获取；不再使用全局随机池或覆盖 Forge 随机函数。需使用支持该 API 的微信基础库。不要将真实个人信息提交到未受信任或未启用 HTTPS 的服务。

Server 业务接口的成功响应统一使用 `{ code, message, data }` 格式。SDK 在普通和解密后的响应中都会保留此 `Result<T>` 包装，业务内容位于 `data`；不符合该格式的成功响应会被识别为无效响应。

## 共享 SDK

独立 SDK 位于 `sdk/`，可单独打包发布到团队私有 npm 仓库，接入方式见 [SDK 文档](sdk/README.md)。核心逻辑不依赖 `wx`，微信适配器负责网络和安全随机数，每个客户端实例独立管理公钥缓存。

本演示直接通过 `require('../sdk/index')` 接入，无需 npm 构建。`utils/api.js` 仅将 SDK 的显式诊断结果转换成页面展示格式；其他团队默认使用 `client.send()` 获取业务响应，不应复用演示中的明文/密文对照输出。
