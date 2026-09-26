package com.ikea.crypto.server.api;

import com.ikea.crypto.common.CryptoConstants;
import com.ikea.crypto.common.PlainData;
import com.ikea.crypto.common.SensitiveData;
import com.ikea.crypto.common.rsa.RsaPublicKeyResponse;
import com.ikea.crypto.common.rsa.SessionKeyTransport;
import com.ikea.crypto.server.advice.DecryptRequest;
import com.ikea.crypto.server.advice.EncryptResponse;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.model.CryptoAlgorithm;
import com.ikea.crypto.server.service.RsaCryptoServer;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@RestController
@Validated
@RequestMapping("/crypto/server/rsa")
public class RsaServerController {

    private final RsaCryptoServer rsaCryptoServer;

    public RsaServerController(RsaCryptoServer rsaCryptoServer) {
        this.rsaCryptoServer = rsaCryptoServer;
    }

    @GetMapping("/public-key")
    public RsaPublicKeyResponse getRsaPublicKey() {
        return rsaCryptoServer.getPublicKey();
    }

    @PostMapping("/bidirectional")
    @DecryptRequest(CryptoAlgorithm.RSA)
    @EncryptResponse(CryptoAlgorithm.RSA)
    public SensitiveData bidirectionalRsaEncrypt(@Valid @RequestBody SensitiveData request) {
        return new SensitiveData("mock rsa response for request - " + request.data());
    }

    @PostMapping("/request-only")
    @DecryptRequest(CryptoAlgorithm.RSA)
    public PlainData requestOnlyRsaEncrypt(@Valid @RequestBody SensitiveData request) {
        return new PlainData("mock plain response for request - " + request.data());
    }

    @PostMapping("/response-only")
    @EncryptResponse(CryptoAlgorithm.RSA)
    public SensitiveData responseOnlyRsaEncrypt(
            @RequestBody(required = false)
            PlainData request,
            @RequestHeader(CryptoConstants.HEADER_CLIENT_SESSION_KEY) @NotBlank(message = "client session key is required for response-only RSA encryption")
            String sessionKeyBase64,
            @RequestHeader(CryptoConstants.HEADER_CLIENT_SESSION_IV) @NotBlank(message = "client session IV is required for response-only RSA encryption")
            String sessionIvBase64
    ) {
        SessionKeyTransport sessionTransport = new SessionKeyTransport(sessionKeyBase64, sessionIvBase64);
        CryptoSessionContextAccessor.setCryptoSessionContext(CryptoSessionContext.rsaResponseOnly(sessionTransport));

        return new SensitiveData(
                "mock rsa response for request - " + (request == null || request.data() == null ? "null" : request.data())
        );
    }

}
