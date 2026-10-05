# 使用 mitmproxy 抓取微信小程序 HTTPS 流量

以下步骤用于本地开发调试。示例使用 `9080` 作为代理端口、`9081` 作为 mitmweb 管理页面端口，Kong 通过 `18443` 转发到本机。

以下命令除特别说明外，均在仓库根目录执行。

## 1. 安装 mitmproxy

macOS 安装：

```bash
brew install mitmproxy
```

## 2. 准备 Kong

如果 Kong 已部署且当前证书仍有效、SAN 包含 `DNS:local.kong.test`，可直接进入第 3 步，无需重新生成证书或更新 Secret。

首次部署推荐直接使用 Kong 部署脚本。确认根目录 `.env` 中配置：

```dotenv
KONG_TLS_CERT_FILE=certs/kong.crt
KONG_TLS_KEY_FILE=certs/kong.key
```

在仓库根目录运行（要求 Kubernetes context 为 `docker-desktop`，并已完成 Vault、Server 等部署前置配置，见 [Kong 部署文档](kong/README.md#部署到-kubernetes)）：

```bash
./kong/scripts/deploy-to-k8s.sh
```

部署脚本会将配置的证书和私钥写入 `kong/encryptpii-kong-tls` Secret，并重启 Kong：

- 默认路径的两个文件均不存在时，自动调用 `scripts/create-kong-certificate.sh`，生成 SAN 包含 `localhost` 和 `local.kong.test`、有效期 365 天的证书，私钥权限为 `600`。
- 已有证书和私钥会直接复用，不会自动重新签发。
- 仅缺少其中一个文件，或自定义路径的文件缺失时，部署会报错，不会覆盖已有文件。

`kong/scripts/install-to-kong.sh` 使用同一部署流程。已有镜像时可添加 `--skip-build` 跳过构建。

仅需提前创建证书而不部署 Kong 时，可运行 `./scripts/create-kong-certificate.sh`。已有证书过期或 SAN 不匹配时，确认需要替换后运行：

```bash
./scripts/create-kong-certificate.sh --force
```

重新签发后可重新运行 Kong 部署脚本；若只更新证书、不修改其他部署配置，也可手动更新 TLS Secret 并重启 Kong：

```bash
kubectl -n kong create secret tls encryptpii-kong-tls \
  --cert=certs/kong.crt --key=certs/kong.key \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n kong rollout restart deployment/encryptpii-kong
kubectl -n kong rollout status deployment/encryptpii-kong --timeout=180s
```

## 3. 转发 Kong 端口

另开一个终端，启动 Kubernetes 端口转发并保持运行：

```bash
kubectl -n kong port-forward service/encryptpii-kong 18443:8443
```

## 4. 配置小程序访问地址

在 `/etc/hosts` 中添加：

```text
127.0.0.1 local.kong.test
```

这会将 `local.kong.test` 解析到本机，使 mitmweb 能将请求转发到上一步的 `18443` 端口。

将 `wechat/config.js` 中的 `KONG_BASE_URL` 设置为：

```js
const KONG_BASE_URL = 'https://local.kong.test:18443';
```

## 5. 启动 mitmweb

另开一个终端，在仓库根目录运行：

```bash
mitmweb -p 9080 --web-port 9081 \
  --set ssl_verify_upstream_trusted_ca="$(pwd)/certs/kong.crt"
```

保持终端运行。该命令监听代理端口 `9080` 和管理页面端口 `9081`，并显式信任 Kong 自签名证书，验证 **mitmweb → Kong** 的 TLS 连接。因此，此抓包流程不需要执行 `trust-kong-certificate.sh`，也不需要使用 `ssl_insecure=true` 关闭上游校验。

如果 Kong 使用 mitmweb 已信任的 CA 签发的有效证书且域名匹配，可省略 `--set ssl_verify_upstream_trusted_ca=...`。若 `.env` 配置了自定义证书路径，此处也应使用对应的证书文件。

只有不经代理、直接连接自签名 Kong，且客户端使用 macOS 系统信任库校验证书时，才可能需要运行 `./scripts/trust-kong-certificate.sh`。使用 `curl --cacert certs/kong.crt` 直接访问则无需系统钥匙串信任。

## 6. 配置微信开发者工具并按需信任代理证书

在微信开发者工具中：

1. 本地调试若需要跳过域名和证书校验，打开 **详情 → 本地设置**，勾选 **不校验合法域名、web-view（业务域名）、TLS 版本以及 HTTPS 证书**。
2. 打开 **设置 → 代理设置**，选择手动代理，填写 `127.0.0.1:9080` 并保存。

如果“不校验 HTTPS 证书”设置已生效，通常无需导入 mitmproxy CA，可直接重启开发者工具进入第 7 步。这个设置只影响客户端，不会关闭 mitmweb 对 Kong 的证书校验。

如果保留客户端证书校验，且尚未信任当前 mitmproxy CA，则需要让客户端信任 **微信开发者工具 → mitmweb** 这一段连接。首次启动 mitmweb 后会生成 `~/.mitmproxy/mitmproxy-ca-cert.pem`；对于使用 macOS 系统信任库的客户端，运行：

```bash
./scripts/trust-mitmproxy-certificate.sh
```

不要在脚本前加 `sudo`，以免读取错误用户的证书目录；脚本会在导入系统钥匙串时请求管理员授权。也可以运行 `open ~/.mitmproxy/mitmproxy-ca-cert.pem`，手动导入“登录”钥匙串，在证书的“信任”中设置为“始终信任”。

已信任当前 CA 时不必重复导入；CA 重新生成后才需按需重新信任。使用独立信任库的客户端需在自身配置中导入 CA。证书信任不能替代合法域名等其他校验配置。

完成代理和必要的信任配置后，重启微信开发者工具，使配置生效。

## 7. 发起请求并查看抓包结果

在浏览器打开 [http://127.0.0.1:9081](http://127.0.0.1:9081)，然后在小程序页面触发普通传输或加密传输演示。

在 mitmweb 中找到发往 `local.kong.test:18443` 的请求，点击查看请求方法、路径、请求头、请求体和响应内容。普通传输可查看业务明文；应用层加密模式中，被加密的请求或响应体仍然是密文，HTTPS 抓包不会自动解开应用层加密。

## 8. 结束抓包

将微信开发者工具的代理设置恢复为抓包前的配置，在 mitmweb 和端口转发终端分别按 `Ctrl+C` 停止进程。如果曾导入 mitmproxy CA 且不再需要，可在钥匙串访问中移除该证书或其信任。只信任来源确认可信的本机 CA，不应长期保留不再需要的信任。

## 常见问题

- **页面没有请求**：确认 mitmweb 和 `kubectl port-forward` 都在运行，并检查开发者工具代理地址是否为 `127.0.0.1:9080`。
- **连接 Kong 失败**：确认 `/etc/hosts` 中有 `local.kong.test`，且 `wechat/config.js` 使用 `https://local.kong.test:18443`。
- **无法连接代理**：检查 `~/.mitmproxy/config.yaml` 中的端口是否为 `9080` 和 `9081`，并确认没有其他程序占用这些端口。
- **客户端提示不受信任的证书**：若经 mitmweb 访问 HTTPS 且客户端会校验证书，按第 6 步信任当前 mitmproxy CA，然后重启客户端。
- **mitmweb 报上游证书校验失败**：检查指定的 `certs/kong.crt` 是否与 Kong 当前证书一致、证书是否有效，以及 SAN 是否包含 `local.kong.test`。导入 mitmproxy CA 不能解决上游校验失败，信任 Kong 证书也不能修复 SAN 不匹配。