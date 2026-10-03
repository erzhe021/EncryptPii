package com.ikea.crypto.server.api;

import com.ikea.crypto.server.model.DemoPlainRequest;
import com.ikea.crypto.server.model.DemoPlainResponse;
import com.ikea.crypto.server.model.DemoSensitiveRequest;
import com.ikea.crypto.server.model.DemoSensitiveResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
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
    public DemoSensitiveResponse bidirectional(
            @RequestHeader(value = GATEWAY_TOKEN_HEADER, required = false) String suppliedToken,
            @RequestBody DemoSensitiveRequest request) {
        verifyGatewayToken(suppliedToken);
        return new DemoSensitiveResponse(request.name(), request.phone(), request.email(), request.address(),
                "This is bidirectional encryption demo");
    }

    @PostMapping("/request-only")
    public DemoPlainResponse requestOnly(
            @RequestHeader(value = GATEWAY_TOKEN_HEADER, required = false) String suppliedToken,
            @RequestBody DemoSensitiveRequest request) {
        verifyGatewayToken(suppliedToken);
        return new DemoPlainResponse("1234-5678-9012-3456", 3, 1500L,
                "This is request-only encryption demo");
    }

    @PostMapping("/response-only")
    public DemoSensitiveResponse responseOnly(
            @RequestHeader(value = GATEWAY_TOKEN_HEADER, required = false) String suppliedToken,
            @RequestBody(required = false) DemoPlainRequest request) {
        verifyGatewayToken(suppliedToken);
        return new DemoSensitiveResponse("eric", "13764641531", "eric.zheng@ingka.ikea.com",
                "上海市长宁区荟聚中心办公A楼", "This is response-only encryption demo");
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
