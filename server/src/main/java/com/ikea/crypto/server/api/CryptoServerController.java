package com.ikea.crypto.server.api;

import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.model.demo.PlainData;
import com.ikea.crypto.common.model.demo.SensitiveData;
import com.ikea.crypto.common.model.payload.PublicKeyResponse;
import com.ikea.crypto.common.model.payload.SessionKeyTransport;
import com.ikea.crypto.server.advice.DecryptRequest;
import com.ikea.crypto.server.advice.EncryptResponse;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.service.CryptoServer;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/crypto/server")
@Validated
@Slf4j
public class CryptoServerController {

    private final CryptoServer cryptoServer;

    public CryptoServerController(CryptoServer cryptoServer) {
        this.cryptoServer = cryptoServer;
    }

    @GetMapping("/public-key")
    public PublicKeyResponse getPublicKey() {
        log.debug("【api called】start to retrieving RSA public key");
        return cryptoServer.getPublicKey();
    }

    @PostMapping("/bidirectional")
    @DecryptRequest
    @EncryptResponse
    public SensitiveData bidirectionalEncrypt(@Valid @RequestBody SensitiveData request) {
        log.debug("【api called】start to processing bidirectional RSA encryption, request data: {}", request.data());
        return new SensitiveData("mock rsa response for request - " + request.data());
    }

    @PostMapping("/request-only")
    @DecryptRequest
    public PlainData requestOnlyEncrypt(@Valid @RequestBody SensitiveData request) {
        log.debug("【api called】start to processing request-only RSA encryption, request data: {}", request.data());
        return new PlainData("mock plain response for request - " + request.data());
    }

    @PostMapping("/response-only")
    @EncryptResponse
    public SensitiveData responseOnlyEncrypt(
            @RequestBody(required = false)
            PlainData request,
            @RequestHeader(CryptoConstants.HEADER_ENCRYPTED_SESSION_KEY) @NotBlank(message = "client session key is required for response-only RSA encryption")
            String sessionKeyBase64
    ) {
        log.debug("【api called】start to processing response-only RSA encryption, request data: {}", request == null ? "null" : request.data());
        SessionKeyTransport sessionTransport = new SessionKeyTransport(sessionKeyBase64);
        CryptoSessionContextAccessor.setCryptoSessionContext(CryptoSessionContext.responseOnly(sessionTransport));

        return new SensitiveData(
                "mock rsa response for request - " + (request == null || request.data() == null ? "null" : request.data())
        );
    }

}
