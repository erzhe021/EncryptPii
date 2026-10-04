# 使用 mitmproxy 抓取微信小程序 HTTPS 流量

以下步骤用于本地开发调试。示例使用 `9080` 作为代理端口、`9081` 作为 mitmweb 管理页面端口，Kong 通过 `18443` 转发到本机。

## 1. 安装并启动 mitmproxy

macOS 安装：

```bash
brew install mitmproxy
```

在 `~/.mitmproxy/config.yaml` 中设置端口：

```yaml
listen_port: 9080
web_port: 9081
```

启动代理：

```bash
mitmweb --set ssl_insecure=true
```

保持该终端运行。`ssl_insecure=true` 用于本地调试时忽略上游 Kong 证书校验，不要用于生产环境。

## 2. 信任 mitmproxy CA 证书

首次启动 mitmproxy 后，它会生成 CA 证书。将 `~/.mitmproxy/mitmproxy-ca-cert.pem` 加入 macOS 钥匙串并设为信任：

1. 在终端运行 `open ~/.mitmproxy/mitmproxy-ca-cert.pem`，在钥匙串访问中打开该证书。
2. 将证书添加到“登录”钥匙串；如系统提示，输入 macOS 用户密码。
3. 双击证书，在“信任”中将“使用此证书时”设为“始终信任”，然后关闭窗口并确认授权。

只信任本机 mitmproxy 生成的 CA 证书。调试结束后，可在钥匙串访问中删除该证书，避免后续流量继续被本地代理解密。

## 3. 转发 Kong 端口

另开一个终端，启动 Kubernetes 端口转发并保持运行：

```bash
kubectl -n kong port-forward service/encryptpii-kong 18443:8443
```

## 4. 配置本地域名

在 `/etc/hosts` 中添加：

```text
127.0.0.1 local.kong.test
```

将 `wechat/config.js` 中的 `KONG_BASE_URL` 设置为：

```js
const KONG_BASE_URL = 'https://local.kong.test:18443';
```

## 5. 配置微信开发者工具代理

在微信开发者工具中：

1. 打开 **详情 → 本地设置**，勾选 **不校验合法域名、web-view（业务域名）、TLS 版本以及 HTTPS 证书**。
2. 打开 **设置 → 代理设置**，选择手动代理，填写 `127.0.0.1:9080` 并保存。
3. 重启微信开发者工具，使代理和小程序配置生效。

## 6. 查看请求

在浏览器打开 [http://127.0.0.1:9081](http://127.0.0.1:9081)，即可查看经 mitmproxy 转发的请求。

## 常见问题

- **页面没有请求**：确认 mitmweb 和 `kubectl port-forward` 都在运行，并检查开发者工具代理地址是否为 `127.0.0.1:9080`。
- **连接 Kong 失败**：确认 `/etc/hosts` 中有 `local.kong.test`，且 `wechat/config.js` 使用 `https://local.kong.test:18443`。
- **无法连接代理**：检查 `~/.mitmproxy/config.yaml` 中的端口是否为 `9080` 和 `9081`，并确认没有其他程序占用这些端口。
