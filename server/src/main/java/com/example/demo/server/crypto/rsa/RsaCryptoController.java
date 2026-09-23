package com.example.demo.server.crypto.rsa;

import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.crypto.rsa.RsaDecryptDataResponse;
import com.example.demo.crypto.rsa.RsaPublicKeyResponse;
import org.springframework.web.bind.annotation.*;

import java.security.GeneralSecurityException;

@RestController
@RequestMapping("/api/crypto/rsa")
public class RsaCryptoController {

    private final RsaCryptoService rsaCryptoService;

    public RsaCryptoController(RsaCryptoService rsaCryptoService) {
        this.rsaCryptoService = rsaCryptoService;
    }

    @GetMapping("/public-key")
    public RsaPublicKeyResponse getRsaPublicKey() {
        return rsaCryptoService.getPublicKey();
    }

    @PostMapping("/decrypt")
    public RsaDecryptDataResponse decryptRsa(@RequestBody RsaCipherPayload payload) throws GeneralSecurityException {
        return new RsaDecryptDataResponse(rsaCryptoService.decrypt(payload));
    }
}
