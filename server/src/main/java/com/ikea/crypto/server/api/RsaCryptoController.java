package com.ikea.crypto.server.api;

import com.ikea.crypto.common.CryptoConstants;
import com.ikea.crypto.common.PlainData;
import com.ikea.crypto.common.SensitiveData;
import com.ikea.crypto.common.rsa.SessionKeyTransport;
import com.ikea.crypto.common.rsa.RsaPublicKeyResponse;
import com.ikea.crypto.server.model.CryptoAlgorithm;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.advice.DecryptRequest;
import com.ikea.crypto.server.advice.EncryptResponse;
import com.ikea.crypto.server.service.RsaCryptoServer;
import org.springframework.web.bind.annotation.*;

@RestController
public class RsaCryptoController {

    private final RsaCryptoServer rsaCryptoServer;

    public RsaCryptoController(RsaCryptoServer rsaCryptoServer) {
        this.rsaCryptoServer = rsaCryptoServer;
    }

    @GetMapping("${crypto.server.endpoints.rsa.public-key:/crypto/server/rsa/public-key}")
    public RsaPublicKeyResponse getRsaPublicKey() {
        return rsaCryptoServer.getPublicKey();
    }

    @PostMapping("${crypto.server.endpoints.rsa.bidirectional:/crypto/server/rsa/bidirectional}")
    @DecryptRequest(CryptoAlgorithm.RSA)
    @EncryptResponse(CryptoAlgorithm.RSA)
    public SensitiveData bidirectionalRsaEncrypt(@RequestBody SensitiveData request) {
        return new SensitiveData("mock rsa response for request - " + request.data());
    }

    @PostMapping("${crypto.server.endpoints.rsa.request-only:/crypto/server/rsa/request-only}")
    @DecryptRequest(CryptoAlgorithm.RSA)
    public PlainData requestOnlyRsaEncrypt(@RequestBody SensitiveData request) {
        return new PlainData("mock plain response for request - " + request.data());
    }

    @PostMapping("${crypto.server.endpoints.rsa.response-only:/crypto/server/rsa/response-only}")
    @EncryptResponse(CryptoAlgorithm.RSA)
    public SensitiveData responseOnlyRsaEncrypt(
            @RequestBody(required = false) PlainData request,
            @RequestHeader(value = CryptoConstants.HEADER_CLIENT_SESSION_KEY, required = false) String sessionKeyBase64,
            @RequestHeader(value = CryptoConstants.HEADER_CLIENT_SESSION_IV, required = false) String sessionIvBase64
    ) {
        if (sessionKeyBase64 == null || sessionKeyBase64.isBlank()) {
            throw new IllegalArgumentException("client session key is required for response-only RSA encryption");
        }
        if (sessionIvBase64 == null || sessionIvBase64.isBlank()) {
            throw new IllegalArgumentException("client session IV is required for response-only RSA encryption");
        }

        SessionKeyTransport sessionTransport = new SessionKeyTransport(sessionKeyBase64, sessionIvBase64);
        CryptoSessionContextAccessor.setCryptoSessionContext(CryptoSessionContext.rsaResponseOnly(sessionTransport));

        return new SensitiveData("mock rsa response for request - " + (request == null || request.data() == null ? "null" : request.data()));

    }

}
