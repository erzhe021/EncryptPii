package com.ikea.crypto.server.api;

import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.model.SessionKeyTransport;
import com.ikea.crypto.server.advice.DecryptRequest;
import com.ikea.crypto.server.advice.EncryptResponse;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.model.DemoPlainRequest;
import com.ikea.crypto.server.model.DemoPlainResponse;
import com.ikea.crypto.server.model.DemoSensitiveRequest;
import com.ikea.crypto.server.model.DemoSensitiveResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

/**
 * Demo business controller showcasing usage of @DecryptRequest and @EncryptResponse.
 * Public key retrieval and key rotation endpoints are auto-configured by CryptoKeyEndpoint in the SDK.
 */
@RestController
@RequestMapping("/crypto/server")
@Validated
@Slf4j
public class CryptoServerController {

    @PostMapping("/bidirectional")
    @DecryptRequest
    @EncryptResponse
    public DemoSensitiveResponse bidirectionalEncrypt(@Valid @RequestBody DemoSensitiveRequest request) {
        log.debug("【api called】start to processing bidirectional RSA encryption, request data: {}", request);
        return new DemoSensitiveResponse(request, "This is bidirectional encryption demo");
    }

    @PostMapping("/request-only")
    @DecryptRequest
    public DemoPlainResponse requestOnlyEncrypt(@Valid @RequestBody DemoSensitiveRequest request) {
        log.debug("【api called】start to processing request-only RSA encryption, request data: {}", request);
        return new DemoPlainResponse("1234-5678-9012-3456", 3, 1500L, "This is request-only encryption demo");
    }

    @PostMapping("/response-only")
    @EncryptResponse
    public DemoSensitiveResponse responseOnlyEncrypt(
            @RequestBody(required = false)
            DemoPlainRequest request,
            @RequestHeader(CryptoConstants.HEADER_CRYPTO_SESSION_KEY) @NotBlank(message = "client session key is required for response-only RSA encryption")
            String sessionKeyBase64,
            @RequestHeader(value = CryptoConstants.HEADER_KEY_ID, required = false)
            String keyId
    ) {
        log.debug("【api called】start to processing response-only RSA encryption, keyId={}, request data: {}", keyId, request == null ? "null" : request);
        SessionKeyTransport sessionTransport = new SessionKeyTransport(keyId, sessionKeyBase64);
        CryptoSessionContextAccessor.setCryptoSessionContext(CryptoSessionContext.responseOnly(sessionTransport));
        return new DemoSensitiveResponse("eric", "13764641531", "eric.zheng@ingka.ikea.com", "上海市长宁区荟聚中心办公A楼", "This is response-only encryption demo");
    }
}

