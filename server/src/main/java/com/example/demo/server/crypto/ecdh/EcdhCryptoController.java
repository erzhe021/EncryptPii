package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhDecryptDataResponse;
import com.example.demo.crypto.ecdh.EcdhPublicKeyResponse;
import org.springframework.web.bind.annotation.*;

import java.security.GeneralSecurityException;

@RestController
@RequestMapping("/api/crypto/ecdh")
public class EcdhCryptoController {

    private final EcdhCryptoService ecdhCryptoService;

    public EcdhCryptoController(EcdhCryptoService ecdhCryptoService) {
        this.ecdhCryptoService = ecdhCryptoService;
    }

    @GetMapping("/public-key")
    public EcdhPublicKeyResponse getEcdhPublicKey() throws GeneralSecurityException {
        return ecdhCryptoService.getPublicKey();
    }

    @PostMapping("/decrypt")
    public EcdhDecryptDataResponse decryptEcdh(@RequestBody EcdhCipherPayload payload) throws GeneralSecurityException {
        return new EcdhDecryptDataResponse(ecdhCryptoService.decrypt(payload));
    }
}
