# EncryptPii 微信小程序

此小程序提供普通传输、双向加密、请求加密和响应加密四种演示。小程序直接连接 Kong：从 Kong 获取 RSA 公钥，在本机执行 RSA-OAEP-SHA-256（MGF1-SHA-1）和 AES-256-GCM 加解密，再按 Kong 插件协议提交请求。

## 配置与运行

1. 修改 `config.js` 中的 `KONG_BASE_URL`，设置为手机可访问的 Kong HTTPS 域名，不要填写 Client、Server 或 Kong Admin API 地址。
2. 在微信开发者工具中导入 `wechat` 目录并运行。`project.config.json` 使用 `touristappid`，发布前请替换为小程序 AppID。
3. 在小程序管理后台将 Kong 域名加入 `request` 合法域名；生产环境必须使用 HTTPS。

## 接口映射

| 小程序模式 | Kong 路由 |
| --- | --- |
| 获取公钥 | `GET /crypto/server/public-key` |
| 普通传输 | `POST /plain/server/normal` |
| 双向加密 | `POST /crypto/server/bidirectional` |
| 请求加密 | `POST /crypto/server/request-only` |
| 响应加密 | `POST /crypto/server/response-only` |

请求加密模式与 Java SDK 使用相同的 RSA OAEP 摘要参数、AES-GCM IV 和认证标签格式。响应加密模式通过 `X-STC-KEY-ID` 和 `X-STC-SESSION-KEY` 请求头发送 RSA 加密的 AES 会话密钥。公钥在内存中缓存至过期；收到 `KEY_EXPIRED` 时刷新并最多重试一次。

RSA/AES 实现使用 node-forge 浏览器 bundle，见 `lib/FORGE-LICENSE.txt`。会话密钥、IV 和 RSA OAEP 填充随机数均使用微信 `wx.getRandomValues`；需使用支持该 API 的微信基础库。不要将真实个人信息提交到未受信任或未启用 HTTPS 的服务。
