package com.example.demo.server.crypto;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/secure")
public class CryptoController {

    @PostMapping("/rsa/echo")
    @DecryptRequest(CryptoAlgorithm.RSA)
    @EncryptResponse(CryptoAlgorithm.RSA)
    public SensitiveDataResponse rsaEcho(@RequestBody SensitiveDataRequest request) {
        return new SensitiveDataResponse(request.data());
    }

    @PostMapping("/ecdh/echo")
    @DecryptRequest(CryptoAlgorithm.ECDH)
    @EncryptResponse(CryptoAlgorithm.ECDH)
    public SensitiveDataResponse ecdhEcho(@RequestBody SensitiveDataRequest request) {
        return new SensitiveDataResponse(request.data());
    }
}
