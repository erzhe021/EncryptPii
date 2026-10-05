# Java Client 信任本地 HTTPS 证书

本文用于本地开发：为 Java Client 创建独立的 PKCS12 truststore，不修改 JDK 全局 `cacerts`，也不关闭证书或主机名校验。以下命令均在仓库根目录执行，不是在 `client/` 目录执行。

## 1. 确认错误原因和需要信任的证书

如果请求出现以下错误，说明 JVM 无法建立服务器证书的信任链：

```text
SunCertPathBuilderException: unable to find valid certification path to requested target
```

本项目的 `CryptoHttpClient` 使用 `HttpClient.newHttpClient()`，默认依赖 JVM 的信任配置。将证书加入 macOS 钥匙串，通常不会使 JVM 自动信任它。

外层的 `Failed to fetch RSA public key from server` 是对网络异常的包装：HTTPS 握手失败时，Client 尚未取得业务 RSA 公钥。TLS 证书与业务加密使用的 RSA 公钥不是同一回事。

根据实际连接方式选择证书：

| 连接方式 | Java Client 需要信任的证书 |
| --- | --- |
| Client 直接连接 Kong | `certs/kong.crt` |
| Client 经 mitmproxy 解密代理连接 Kong | `~/.mitmproxy/mitmproxy-ca-cert.pem` |

## 2. 创建并导入 truststore

使用运行 Client 的 JDK 所提供的 `keytool`。如果 `JAVA_HOME` 已指向该 JDK，可将下方的 `keytool` 替换为 `"$JAVA_HOME/bin/keytool"`。

直接连接 Kong 时，执行：

```bash
keytool -importcert \
  -alias kong-local \
  -file certs/kong.crt \
  -keystore certs/client-truststore.p12 \
  -storetype PKCS12
```

首次创建时按提示设置 truststore 密码，核对证书信息后确认导入。可先查看本地证书的 SHA-256 指纹：

```bash
openssl x509 -in certs/kong.crt -noout -fingerprint -sha256
```

仅当 Client 经过 mitmproxy 解密抓包时，才需要导入代理 CA；可使用同一 truststore，并使用不同的别名：

```bash
keytool -importcert \
  -alias mitmproxy-local \
  -file "$HOME/.mitmproxy/mitmproxy-ca-cert.pem" \
  -keystore certs/client-truststore.p12 \
  -storetype PKCS12
```

这只配置信任，不会自动让 Java Client 使用代理。代理连接需按第 5 步单独配置，且 mitmproxy 仍需信任上游 Kong 的证书。如果尚未生成代理 CA，先按第 5 步启动 mitmweb，再执行上述导入命令。已导入相应证书且证书未更换时，无需重复导入。

查看已导入的证书：

```bash
keytool -list -v \
  -keystore certs/client-truststore.p12 \
  -storetype PKCS12
```

## 3. 配置 IntelliJ 的 Client 运行参数

打开 **Run → Edit Configurations**，选择 Client 的运行配置。如未显示 **VM options**，通过 **Modify options → Add VM options** 启用。

添加以下参数，将路径和密码替换为实际值：

```text
-Djavax.net.ssl.trustStore=/absolute/path/to/EncryptPii/certs/client-truststore.p12
-Djavax.net.ssl.trustStoreType=PKCS12
-Djavax.net.ssl.trustStorePassword=YOUR_TRUSTSTORE_PASSWORD
```

填写在 **VM options**，不是 **Program arguments**。路径包含空格时，将路径值用双引号包围；密码包含空格时也需正确引用。不要将含密码的共享运行配置提交到 Git。

显式指定这个 truststore 后，默认信任配置不会自动与它合并。如果 Client 还需要连接其他 HTTPS 服务，也要确保此 truststore 包含那些服务所需的可信 CA。

## 4. 直接连接 Kong

直接连接时移除 Client 运行配置中的代理参数，并确保没有其他代理配置让请求经过 mitmproxy。truststore 需包含第 2 步导入的 Kong 证书。需要代理抓包时，改按第 5 步操作。

确认 Kong 的端口转发正在运行：

```bash
kubectl -n kong port-forward service/encryptpii-kong 18443:8443
```

在 `client/src/main/resources/application.yml` 中配置：

```yaml
crypto:
  server:
    base-url: https://localhost:18443
```

完全停止并重新启动 Client，再调用演示接口。仅修改运行参数而不重启，无法更新已创建的 HTTP 客户端和 TLS 上下文。

证书 SAN 必须包含 URL 的主机名。本项目的证书创建脚本生成包含 `localhost` 和 `local.kong.test` 的证书；添加信任不能修复主机名不匹配。

## 5. 通过 mitmproxy 抓取 Client 的 HTTPS 请求

当前 `CryptoHttpClient` 使用 `HttpClient.newHttpClient()`，可通过 JVM 代理参数接入 mitmproxy，无需修改 Java 代码。以下配置用于在本机运行的 Client，不适用于直接在 Kubernetes Pod 中使用 `127.0.0.1` 访问宿主机代理。

### 启动端口转发和代理

在两个终端分别运行并保持运行：

```bash
kubectl -n kong port-forward service/encryptpii-kong 18443:8443
```

```bash
mitmweb -p 9080 --web-port 9081 \
  --set ssl_verify_upstream_trusted_ca="$(pwd)/certs/kong.crt" \
  --set 'allow_hosts=^local\.kong\.test(:18443)?$'
```

`ssl_verify_upstream_trusted_ca` 配置 **mitmproxy → Kong** 的信任。`allow_hosts` 限定解密范围，其他域名仅透传；这不是客户端代理绕过配置。

### 准备 Java 信任配置

按第 2 步将 `~/.mitmproxy/mitmproxy-ca-cert.pem` 导入 `certs/client-truststore.p12`。这配置的是 **Client → mitmproxy** 的信任，仅导入 Kong 证书不能使 Client 接受代理签发的证书。无需将代理 CA 加入 macOS 钥匙串。

### 添加 JVM 代理参数

在 IntelliJ 的 Client 运行配置中，使用以下完整 **VM options**，替换路径和密码：

```text
-Dhttps.proxyHost=127.0.0.1
-Dhttps.proxyPort=9080
-Dhttp.nonProxyHosts=
-Djavax.net.ssl.trustStore=/absolute/path/to/EncryptPii/certs/client-truststore.p12
-Djavax.net.ssl.trustStoreType=PKCS12
-Djavax.net.ssl.trustStorePassword=YOUR_TRUSTSTORE_PASSWORD
```

`http.nonProxyHosts` 同样影响 HTTPS；设置为空可避免本地地址被默认绕过代理。该设置会影响 JVM 中使用默认代理选择器的其他请求，应仅用于本地调试。这里不需要 SOCKS 代理，也不能仅依赖 `HTTPS_PROXY` 环境变量让 Java HTTP 客户端使用代理。

### 保持业务地址并重启

确认 `/etc/hosts` 包含：

```text
127.0.0.1 local.kong.test
```

在 `client/src/main/resources/application.yml` 中配置：

```yaml
crypto:
  server:
    base-url: https://local.kong.test:18443
```

不要把 `base-url` 改为代理地址 `http://127.0.0.1:9080`。此处使用 `local.kong.test`，与上面的 `allow_hosts` 解密规则一致；若改用 `localhost`，需同步修改该规则。

完全停止并重新启动 Client，再调用演示接口。在浏览器打开 [http://127.0.0.1:9081](http://127.0.0.1:9081)，查看发往 Kong 的请求和响应。应用层加密的请求或响应仍会以密文显示，解密 TLS 不等于解密业务载荷。

结束抓包后，移除代理 VM options 并重启 Client。如恢复直接连接 Kong，确保 truststore 仍包含 Kong 证书；停止不再需要的 mitmweb 和端口转发进程。

## 6. 证书更换后的处理

如果 Kong 自签名证书已重新签发，需要删除 truststore 中的旧条目，再按第 2 步导入新证书：

```bash
keytool -delete \
  -alias kong-local \
  -keystore certs/client-truststore.p12 \
  -storetype PKCS12
```

mitmproxy CA 重新生成时，同样按需替换 `mitmproxy-local` 条目。更新后重启 Client。调试结束后，不再需要代理 CA 时可删除该条目，避免保留多余信任。

## 常见问题

- **仍提示无法建立信任链**：检查运行配置使用的 truststore 绝对路径、证书别名，以及实际 TLS 对端是否为 Kong 或 mitmproxy；确认应用已完全重启。
- **提示证书别名已存在**：若需要替换证书，先删除对应旧条目，再导入新证书，不要随意覆盖其他信任条目。
- **提示主机名不匹配或证书过期**：重新准备有效且 SAN 匹配的证书，并更新 Kong TLS Secret 和 Client truststore；不要关闭 TLS 校验。
- **提示 truststore 密码错误或文件无法加载**：检查 VM options 中的路径、密码和 `PKCS12` 类型是否与创建时一致。
- **mitmweb 中没有 Client 请求**：检查 JVM 代理参数是否填写在实际使用的运行配置中、`http.nonProxyHosts` 是否为空、Client 是否完全重启，以及 URL 是否匹配 `allow_hosts`。仅导入代理 CA 不会启用代理。
- **mitmweb 提示上游证书校验失败**：检查 `ssl_verify_upstream_trusted_ca` 指向的证书是否与 Kong 当前证书一致，并检查有效期和 SAN；Java truststore 只解决 Client 这一侧的信任。