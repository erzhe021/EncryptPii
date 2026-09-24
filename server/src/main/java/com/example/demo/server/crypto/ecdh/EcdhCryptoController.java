package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.ClientSessionKeyTransport;
import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.PlainData;
import com.example.demo.crypto.SensitiveData;
import com.example.demo.crypto.ecdh.EcdhPublicKeyResponse;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.CryptoSessionContext;
import com.example.demo.server.crypto.DecryptRequest;
import com.example.demo.server.crypto.EncryptResponse;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import java.security.GeneralSecurityException;

@RestController
public class EcdhCryptoController {

    private final EcdhCryptoServer cryptoServer;

    public EcdhCryptoController(EcdhCryptoServer cryptoServer) {
        this.cryptoServer = cryptoServer;
    }

    /**
     * Endpoint to retrieve the server's ECDH public key.
     *
     * @return An EcdhPublicKeyResponse containing the server's ECDH public key.
     * @throws GeneralSecurityException If there is an error generating the public key.
     */
    @GetMapping("/crypto/server/ecdh/public-key")
    public EcdhPublicKeyResponse getEcdhPublicKey() throws GeneralSecurityException {
        return cryptoServer.generateEphemeralEcdhPublicKey();
    }

    /**
     * Endpoint to demonstrate bidirectional ECDH encryption.
     *
     * @param request The request body containing sensitive data to be decrypted.
     * @return A SensitiveData response that will be encrypted using ECDH.
     */
    @PostMapping("/crypto/server/ecdh/bidirectional")
    @DecryptRequest(CryptoAlgorithm.ECDH)
    @EncryptResponse(CryptoAlgorithm.ECDH)
    public SensitiveData bidirectionalECDHEncrypt(@RequestBody SensitiveData request) {
        return new SensitiveData("mock ecdh response for request - " + request.data());
    }

    /**
     * This endpoint demonstrates request-only ECDH encryption.
     * It requires the client to provide the session key and IV in the request headers.
     * The response body is not used for encryption, but it is required to be non-empty for demonstration purposes.
     *
     * @param request The request body containing sensitive data to be decrypted.
     * @return A PlainData response that will not be encrypted.
     */
    @PostMapping("/crypto/server/ecdh/request-only")
    @DecryptRequest(CryptoAlgorithm.ECDH)
    public PlainData requestOnlyEcdhEncrypt(@RequestBody SensitiveData request) {
        return new PlainData("mock plain response for request - " + request.data());
    }

    /**
     * This endpoint demonstrates response-only ECDH encryption.
     * It requires the client to provide the session key and IV in the request headers.
     * The request body is not used for decryption, but it is required to be non-empty for demonstration purposes.
     *
     * @param request The request body containing plain data (not used for decryption).
     * @param sessionKeyBase64 The client's session key in Base64 format, provided in the request header.
     * @param sessionIvBase64 The client's session IV in Base64 format, provided in the request header.
     * @return A PlainData response that will be encrypted using the provided session key and IV.
     */
    @PostMapping("/crypto/server/ecdh/response-only")
    @EncryptResponse(CryptoAlgorithm.ECDH)
    public PlainData responseOnlyEcdhEncrypt(
            @RequestBody PlainData request,
            @RequestHeader(value = CryptoConstants.HEADER_CLIENT_SESSION_KEY, required = false) String sessionKeyBase64,
            @RequestHeader(value = CryptoConstants.HEADER_CLIENT_SESSION_IV, required = false) String sessionIvBase64
    ) {
        if (request == null || request.data() == null || request.data().isBlank()) {
            throw new IllegalArgumentException("request body is required for response-only ECDH encryption");
        }
        if (sessionKeyBase64 == null || sessionKeyBase64.isBlank()) {
            throw new IllegalArgumentException("client session key is required for response-only ECDH encryption");
        }
        if (sessionIvBase64 == null || sessionIvBase64.isBlank()) {
            throw new IllegalArgumentException("client session IV is required for response-only ECDH encryption");
        }

        ClientSessionKeyTransport sessionTransport = new ClientSessionKeyTransport(sessionKeyBase64, sessionIvBase64);
        var requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            requestAttributes.setAttribute(
                    CryptoSessionContext.REQUEST_CONTEXT_KEY,
                    new CryptoSessionContext(CryptoAlgorithm.ECDH, null, sessionTransport),
                    RequestAttributes.SCOPE_REQUEST
            );
        }

        return new PlainData("mock ecdh response for request - " + request.data());
    }

}
