package com.example.demo.server.crypto.rsa;

import com.example.demo.crypto.ClientSessionKeyTransport;
import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.PlainData;
import com.example.demo.crypto.SensitiveData;
import com.example.demo.crypto.rsa.RsaPublicKeyResponse;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.CryptoSessionContext;
import com.example.demo.server.crypto.DecryptRequest;
import com.example.demo.server.crypto.EncryptResponse;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.security.GeneralSecurityException;

@RestController
public class RsaCryptoController {

    private final RsaCryptoServer rsaCryptoServer;

    public RsaCryptoController(RsaCryptoServer rsaCryptoServer) {
        this.rsaCryptoServer = rsaCryptoServer;
    }

    @GetMapping("/crypto/server/rsa/public-key")
    public RsaPublicKeyResponse getRsaPublicKey() {
        return rsaCryptoServer.getPublicKey();
    }

    @PostMapping("/crypto/server/rsa/bidirectional")
    @DecryptRequest(CryptoAlgorithm.RSA)
    @EncryptResponse(CryptoAlgorithm.RSA)
    public SensitiveData bidirectionalRsaEncrypt(@RequestBody SensitiveData request) {
        return new SensitiveData("mock rsa response for request - " + request.data());
    }

    @PostMapping("/crypto/server/rsa/request-only")
    @DecryptRequest(CryptoAlgorithm.RSA)
    public PlainData requestOnlyRsaEncrypt(@RequestBody SensitiveData request) {
        return new PlainData("mock plain response for request - " + request.data());
    }

    @PostMapping("/crypto/server/rsa/response-only")
    @EncryptResponse(CryptoAlgorithm.RSA)
    public PlainData responseOnlyRsaEncrypt(
            @RequestBody PlainData request,
            @RequestHeader(value = CryptoConstants.HEADER_CLIENT_SESSION_KEY, required = false) String sessionKeyBase64,
            @RequestHeader(value = CryptoConstants.HEADER_CLIENT_SESSION_IV, required = false) String sessionIvBase64
    ) throws GeneralSecurityException {
        String data = request == null || request.data() == null ? "Hello, World!" : request.data();
        if (sessionKeyBase64 == null || sessionKeyBase64.isBlank()) {
            throw new IllegalArgumentException("client session key is required for response-only RSA encryption");
        }
        if (sessionIvBase64 == null || sessionIvBase64.isBlank()) {
            throw new IllegalArgumentException("client session IV is required for response-only RSA encryption");
        }

        ClientSessionKeyTransport sessionTransport = new ClientSessionKeyTransport(sessionKeyBase64, sessionIvBase64);
        var requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            requestAttributes.setAttribute(
                    CryptoSessionContext.REQUEST_CONTEXT_KEY,
                    new CryptoSessionContext(CryptoAlgorithm.RSA, null, sessionTransport),
                    RequestAttributes.SCOPE_REQUEST
            );
        }

        return new PlainData("mock rsa response for request - " + data);
    }

}
