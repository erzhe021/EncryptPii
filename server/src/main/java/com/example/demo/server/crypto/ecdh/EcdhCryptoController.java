package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.PlainData;
import com.example.demo.crypto.SensitiveData;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhPublicKeyResponse;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.DecryptRequest;
import com.example.demo.server.crypto.EncryptResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.GeneralSecurityException;

@RestController
public class EcdhCryptoController {

    private final EcdhCryptoService ecdhCryptoService;

    public EcdhCryptoController(EcdhCryptoService ecdhCryptoService) {
        this.ecdhCryptoService = ecdhCryptoService;
    }

    @GetMapping("/crypto/server/ecdh/public-key")
    public EcdhPublicKeyResponse getEcdhPublicKey() throws GeneralSecurityException {
        return ecdhCryptoService.getPublicKey();
    }

    @PostMapping("/crypto/server/ecdh/bidirectional")
    @DecryptRequest(CryptoAlgorithm.ECDH)
    @EncryptResponse(CryptoAlgorithm.ECDH)
    public SensitiveData bidirectionalECDHEncrypt(@RequestBody SensitiveData request) {
        return new SensitiveData("mock ecdh response for request - " + request.data());
    }

    @PostMapping("/crypto/server/ecdh/request-only")
    @DecryptRequest(CryptoAlgorithm.ECDH)
    public PlainData requestOnlyEcdhEncrypt(@RequestBody SensitiveData request) {
        return new PlainData("mock plain response for request - " + request.data());
    }

    @PostMapping("/crypto/server/ecdh/response-only")
    public EcdhCipherPayload responseOnlyEcdhEncrypt(@RequestBody java.util.Map<String, String> request) throws GeneralSecurityException {
        String data = request == null || request.get("data") == null ? "Hello, World!" : request.get("data");
        String responseData = "mock ecdh response for request - " + data;
        String clientPublicKeyBase64 = request.get("clientEphemeralPublicKeyBase64");
        if (clientPublicKeyBase64 == null || clientPublicKeyBase64.isBlank()) {
            throw new IllegalArgumentException("clientEphemeralPublicKeyBase64 is required for response-only ECDH encryption");
        }
        return ecdhCryptoService.encryptWithClientPublicKey(responseData, clientPublicKeyBase64);
    }

}
