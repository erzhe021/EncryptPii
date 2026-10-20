# EncryptPii 微信小程序

此小程序提供普通传输、双向加密、请求加密和响应加密四种传输演示，以及响应加密的客户端异常、系统异常、业务异常三种请求。小程序默认直接连接 Java Server：开启加密后，从 Server 获取 RSA 公钥，在本机执行 RSA-OAEP-SHA-256（MGF1-SHA-1）和 AES-256-GCM 加解密，再按 STC 协议提交请求。

## 配置与运行

1. 在 `config.js` 的 `SERVICES.<service>.baseUrl` 中分别配置各服务地址；`demo` 默认是 `http://localhost:9090`，连接本地 Kong 时可改为 `https://local.kong.test:18443`。真机使用手机可访问的 HTTPS 域名，不要填写 Client 或 Kong Admin API 地址。
2. 在微信开发者工具中导入 `wechat` 目录并运行。发布前请确认 `project.config.json` 中配置的是团队自己的小程序 AppID。
3. 在小程序管理后台将服务域名加入 `request` 合法域名；生产环境必须使用 HTTPS。

应用采用“服务配置注册表 + 客户端工厂”：`config.js` 的 `SERVICES` 按服务标识配置
地址、超时、公钥路径和加密开关；`REQUESTS` 按业务操作配置
`{ service, mode, endpoint }`。`utils/api.js` 根据 `service` 取客户端，
仅把请求参数传入 SDK。SDK 不包含 Team、服务注册表或业务路由。
三个异常演示都使用 `response-only` 模式，仅接口路径不同。

SDK 默认关闭应用层加解密；本演示在 `SERVICES.demo` 中显式配置
`crypto: { enabled: true }`。设为 `false` 时，
所有模式都发送明文且不解密响应，不获取公钥或发送 STC 密钥头。
开关在客户端创建时固定，修改配置后需重新加载小程序。关闭开关不会改写接口路径；
服务端将缺失的 `X-STC-Enabled` 视为 `false`，显式 `false` 同样跳过 STC 处理；
`true` 仅启用协议，实际加解密方向由服务端接口注解决定，SDK 的有效模式必须匹配接口。
连接其他网关时需确认其是否支持此协议及明文请求。

每个业务 POST 都由 SDK 发送字符串 `X-STC-Enabled: true` 或 `false`：
仅当有效模式加密请求或解密响应时为 `true`。即使全局开启，`plain` 仍为 `false`；
全局关闭时四种模式均为 `false`。公钥 GET 不发送此标志。
`X-STC-Enabled`、`X-STC-Key-Id` 和 `X-STC-Session-Key` 为 SDK 保留请求头，
不区分大小写，调用方在全局或单次 `headers` 中设置均会报 `INVALID_ARGUMENT`。
诊断信息 `requestHeaders` 包含启用标志；`stcHeaders` 仍只包含密钥头，明文模式为 `null`。

本地开发者工具可直接使用 `http://localhost:9090`，无需额外开关。
在开发者工具的本地设置中勾选“不校验合法域名、web-view（业务域名）、TLS 版本以及 HTTPS 证书”。
SDK 只允许 `localhost`、`127.0.0.1` 和 `[::1]` 的 HTTP 地址，不允许远程 HTTP。
真机的 `localhost` 指向手机自身；真机和生产环境应使用手机可访问的 HTTPS 地址。
服务仍须实现下表的接口和 STC 协议。

本小程序的加密接口示例使用带 SDK 的 Spring Server。可用内存密钥启动（适合本地演示）：

```sh
./gradlew :server-with-sdk:bootRun --args='--spring.profiles.active=memory'
```

如需使用 Vault，请改用 `server-with-sdk/src/main/resources/application.yml` 的配置。
如果 Server 已在运行，需要先停止旧实例，再重新启动。

## 接口映射

| 小程序模式 | Server 路由 |
| --- | --- |
| 获取公钥 | `GET /sensitive-transport-crypto/public-key` |
| 普通传输 | `POST /plain/server/normal` |
| 双向加密 | `POST /crypto/server/bidirectional` |
| 请求加密（JSON） | `POST /crypto/server/request-only` |
| 响应加密 | `POST /crypto/server/response-only` |
| 客户端异常 | `POST /crypto/server/response-only/client-exception` |
| 系统异常 | `POST /crypto/server/response-only/system-exception` |
| 业务异常 | `POST /crypto/server/response-only/business-exception` |

三种异常请求均使用明文请求内容输入框，开启加密后发送响应加密所需的请求头。客户端异常返回 HTTP 400，系统异常返回 HTTP 500，业务异常返回 HTTP 200 和业务错误码；页面仍展示请求明文、请求密文、响应密文、响应明文和延迟，未使用的密文项显示 `N/A`。

开启加密后，双向、请求加密和响应加密模式均通过 `X-STC-Key-Id` 和 `X-STC-Session-Key` 请求头发送 keyId 与 RSA 加密的 AES 会话密钥；请求密文体只包含 `ivBase64` 和 `encryptedDataBase64`。旧版请求体密钥格式不再兼容。请求加密模式与 Java SDK 使用相同的 RSA OAEP 摘要参数、AES-GCM IV 和认证标签格式。公钥在内存中缓存至配置的提前刷新点；刷新由下一次加密请求触发，不运行后台定时器。收到 `KEY_EXPIRED` 时刷新并最多重试一次，重试会重新生成会话材料及请求头。

请求加密仅支持 JSON：线上请求体是仅包含 `ivBase64` 和 `encryptedDataBase64` 的 JSON 密文信封。

RSA/AES 实现使用 SDK 内置的 node-forge 浏览器 bundle，见 `sdk/lib/FORGE-LICENSE.txt`。会话密钥、IV 和 RSA OAEP seed 均按请求使用微信 `wx.getRandomValues` 获取；不再使用全局随机池或覆盖 Forge 随机函数。需使用支持该 API 的微信基础库。不要将真实个人信息提交到未受信任或未启用 HTTPS 的服务。

Server 业务接口的成功响应统一使用 `{ code, message, data }` 格式。SDK 在普通和解密后的响应中都会保留此 `Result<T>` 包装，业务内容位于 `data`；不符合该格式的成功响应会被识别为无效响应。

## 共享 SDK

独立 SDK 位于 `sdk/`，可单独打包发布到团队私有 npm 仓库，接入方式见 [SDK 文档](sdk/README.md)。核心逻辑不依赖 `wx`，微信适配器负责网络和安全随机数，每个客户端实例独立管理公钥缓存。

本演示直接通过 `require('../sdk/index')` 接入，无需 npm 构建。`utils/api.js` 仅将 SDK 的显式诊断结果转换成页面展示格式；其他团队默认使用 `client.send()` 获取业务响应，不应复用演示中的明文/密文对照输出。

## 多 Team 服务接入

服务标识对应后端安全域，而不是前端页面或 Team 名称。同一后端可共享一个服务配置；
需要独立密钥的后端使用不同标识和公钥入口。即使两个服务共用一个网关域名，
工厂也按服务标识分别创建实例，不会合并公钥缓存：

```js
// config.js 中的注册表示例；配置只保存公开的服务信息，不保存密钥或登录 Token
SERVICES: {
  customer: {
    baseUrl: 'https://api.example.com',
    publicKeyPath: '/customer/public-key',
    crypto: { enabled: true }
  },
  order: {
    baseUrl: 'https://api.example.com',
    publicKeyPath: '/order/public-key',
    crypto: { enabled: true }
  }
},
REQUESTS: {
  updateProfile: {
    service: 'customer',
    mode: 'bidirectional',
    endpoint: '/customer/profile'
  }
}
```

| 文件 | 职责 |
| --- | --- |
| `config.js` | 汇总当前环境的 `SERVICES` 与业务 `REQUESTS` |
| `utils/client-factory.js` | `createClientFactory(services)`：惰性创建、按服务缓存、显式清理 |
| `utils/clients.js` | 创建当前应用共用的工厂，导出 `getClient`、`clear`、`clearAll` |
| 各 Team 的 API 模块 | 固定服务、路径和模式，按请求传入最新认证信息 |

生产业务模块直接调用 `send()`，不使用演示诊断输出：

```js
const { getClient } = require('./utils/clients'); // 按当前模块位置调整相对路径

function updateProfile(data, authorization) {
  return getClient('customer').send({
    mode: 'bidirectional',
    endpoint: '/customer/profile',
    headers: { Authorization: authorization },
    data
  });
}
```

演示包装层也支持 `callApi(requestName, data, headers?)`，返回原有的
`{ ok, error, details }`。Header 仍由 SDK 校验，不能覆盖 STC 保留头。
未知服务、未知业务操作会明确报 `INVALID_ARGUMENT`，不会回退到默认服务。

工厂创建时快照服务配置，获取同一服务会复用实例及公钥缓存；初始化失败不会缓存失败结果。
登录退出、身份或租户切换时调用 `clear(service)` 或 `clearAll()`，后续获取会创建新实例；
已发出的请求继续由旧实例完成，清理不会取消请求，也不保证立即擦除内存。
认证 Header 应逐请求传递，不要把会变化的 Token 固定在注册表中。

修改服务地址、环境或加密开关后，应使用新配置创建工厂（演示中重新加载小程序）。
`clear()` 仅清理客户端，不会重新读取或修改工厂的配置快照。
同一服务需要同时服务多个独立认证/租户上下文时，为每个上下文创建独立工厂，
不要在它们之间复用实例；切换环境也使用新的工厂。

RSA 私钥、Vault 路径权限和密钥轮换由后端管理；客户端只通过各服务的公钥接口获取公钥。
注册多个服务不会自动给单个 Spring 应用增加多密钥域路由，也不替代后端鉴权。
