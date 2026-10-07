package com.ikea.crypto.server.api;

import com.ikea.crypto.server.exception.BusinessException;
import com.ikea.crypto.server.exception.SystemException;
import com.ikea.crypto.server.model.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@RestController
@RequestMapping("/crypto/server")
public class CryptoController {

    private static final String GATEWAY_TOKEN_HEADER = "X-Crypto-Gateway-Token";

    @Value("${sensitive.transport.crypto.kong-gateway-token:}")
    private String gatewayToken;

    @PostMapping("/bidirectional")
    public Result<DemoSensitiveResponse> bidirectional(
            @RequestHeader(value = GATEWAY_TOKEN_HEADER, required = false) String suppliedToken,
            @RequestBody DemoSensitiveRequest request) {
        verifyGatewayToken(suppliedToken);
        return Result.ok(new DemoSensitiveResponse(request.name(), request.phone(), request.email(), request.address(),
                "This is bidirectional encryption demo"));
    }

    @PostMapping("/request-only")
    public Result<DemoPlainResponse> requestOnly(
            @RequestHeader(value = GATEWAY_TOKEN_HEADER, required = false) String suppliedToken,
            @RequestBody DemoSensitiveRequest request) {
        verifyGatewayToken(suppliedToken);
        return Result.ok(new DemoPlainResponse("1234-5678-9012-3456", 3, 1500L,
                "This is request-only encryption demo"));
    }

    @PostMapping("/response-only")
    public Result<DemoSensitiveResponse> responseOnly(
            @RequestHeader(value = GATEWAY_TOKEN_HEADER, required = false) String suppliedToken,
            @RequestBody(required = false) DemoPlainRequest request) {
        verifyGatewayToken(suppliedToken);
        return Result.ok(new DemoSensitiveResponse("张三", "11111111111", "zhangsan@example.com",
                "上海市长宁区某某广场办公A楼", "This is response-only encryption demo"));
    }

    @PostMapping("/response-only/client-exception")
    public Result<DemoSensitiveResponse> responseOnlyClientException(
            @RequestHeader(value = GATEWAY_TOKEN_HEADER, required = false) String suppliedToken,
            @RequestBody(required = false) DemoPlainRequest request) {
        verifyGatewayToken(suppliedToken);
        throw new IllegalArgumentException("demo 4xx exception with sensitive info e.g. mobile: 11111111111");
    }

    @PostMapping("/response-only/system-exception")
    public Result<DemoSensitiveResponse> responseOnlySystemException(
            @RequestHeader(value = GATEWAY_TOKEN_HEADER, required = false) String suppliedToken,
            @RequestBody(required = false) DemoPlainRequest request) {
        verifyGatewayToken(suppliedToken);
        throw new SystemException("demo 5xx exception with sensitive info e.g. mobile: 11111111111");
    }

    @PostMapping("/response-only/business-exception")
    public Result<DemoSensitiveResponse> responseOnlyBizException(
            @RequestHeader(value = GATEWAY_TOKEN_HEADER, required = false) String suppliedToken,
            @RequestBody(required = false) DemoPlainRequest request) {
        verifyGatewayToken(suppliedToken);
        throw new BusinessException("code-123", "demo business exception with sensitive info e.g. mobile: 11111111111");
    }

    private void verifyGatewayToken(String suppliedToken) {
        if (gatewayToken.isBlank()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Kong gateway token is not configured");
        }
        if (suppliedToken == null || !MessageDigest.isEqual(
                gatewayToken.getBytes(StandardCharsets.UTF_8),
                suppliedToken.getBytes(StandardCharsets.UTF_8))) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Request must come through the crypto gateway");
        }
    }
}
