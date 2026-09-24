package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.PlainData;
import com.example.demo.crypto.SensitiveData;
import com.example.demo.crypto.ecdh.EcdhPublicKeyResponse;
import com.example.demo.crypto.ecdh.EcdhResponseOnlyRequest;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.CryptoSessionContext;
import com.example.demo.server.crypto.DecryptRequest;
import com.example.demo.server.crypto.EncryptResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
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
    @GetMapping("${crypto.server.endpoints.ecdh.public-key:/crypto/server/ecdh/public-key}")
    public EcdhPublicKeyResponse getEcdhPublicKey() throws GeneralSecurityException {
        return cryptoServer.generateEphemeralEcdhPublicKey();
    }

    /**
     * Endpoint to demonstrate bidirectional ECDH encryption.
     *
     * @param request The request body containing sensitive data to be decrypted.
     * @return A SensitiveData response that will be encrypted using ECDH.
     */
    @PostMapping("${crypto.server.endpoints.ecdh.bidirectional:/crypto/server/ecdh/bidirectional}")
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
    @PostMapping("${crypto.server.endpoints.ecdh.request-only:/crypto/server/ecdh/request-only}")
    @DecryptRequest(CryptoAlgorithm.ECDH)
    public PlainData requestOnlyEcdhEncrypt(@RequestBody SensitiveData request) {
        return new PlainData("mock plain response for request - " + request.data());
    }

    /**
     * This endpoint demonstrates response-only ECDH encryption.
     * The request body remains plaintext, but it carries the ECDH handshake material required for
     * the server to derive a response key and encrypt only the response.
     *
     * @param request The plaintext request body plus ECDH public key material.
     * @return A PlainData response that will be encrypted using the negotiated ECDH key material.
     */
    @PostMapping("${crypto.server.endpoints.ecdh.response-only:/crypto/server/ecdh/response-only}")
    @EncryptResponse(CryptoAlgorithm.ECDH)
    public PlainData responseOnlyEcdhEncrypt(@RequestBody EcdhResponseOnlyRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request body is required for response-only ECDH encryption");
        }
        if (request.clientEphemeralPublicKeyBase64() == null || request.clientEphemeralPublicKeyBase64().isBlank()) {
            throw new IllegalArgumentException("client ephemeral public key is required for response-only ECDH encryption");
        }
        if (request.serverEphemeralPublicKeyBase64() == null || request.serverEphemeralPublicKeyBase64().isBlank()) {
            throw new IllegalArgumentException("server ephemeral public key is required for response-only ECDH encryption");
        }
        var requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            requestAttributes.setAttribute(
                    CryptoSessionContext.REQUEST_CONTEXT_KEY,
                    new CryptoSessionContext(
                            CryptoAlgorithm.ECDH,
                            new EcdhResponseContext(
                                    request.clientEphemeralPublicKeyBase64(),
                                    request.serverEphemeralPublicKeyBase64()
                            )
                    ),
                    RequestAttributes.SCOPE_REQUEST
            );
        }
        return new PlainData("mock ecdh response for request - " + String.valueOf(request.data()));
    }

    record EcdhResponseContext(String clientEphemeralPublicKeyBase64, String serverEphemeralPublicKeyBase64) {
    }

}
