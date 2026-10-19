# Server SDK 表单请求示例

`POST /crypto/server/form-urlencoded` 演示 SDK 解密后由 Spring MVC 按
`application/x-www-form-urlencoded` 解析请求体。该接口使用 `@DecryptRequest`，
业务参数通过 `MultiValueMap<String, String>` 接收，因而能读取普通字段及重复字段。

```java
@PostMapping(value = "/form-urlencoded", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
@DecryptRequest
public Result<Map<String, String>> formUrlEncoded(
        @RequestBody MultiValueMap<String, String> form) {
    return Result.ok(Map.of("name", form.getFirst("name"), "phone", form.getFirst("phone")));
}
```

客户端使用 `Content-Type: application/x-www-form-urlencoded`。线上 body 将
`ivBase64`、`encryptedDataBase64` 作为 URL 编码表单字段传输；AES-GCM 解密后的
UTF-8 明文才是业务表单，例如 `name=Alice+Smith&phone=123%2B456`。SDK 会先把
加密协议字段规范化后校验、解密，再将明文交给 Spring 的表单转换器解析。

JSON 请求接口（如 `/crypto/server/request-only`）保持原样。表单格式适合简单键值
数据；复杂嵌套结构仍建议使用 JSON。
