package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.ecdh.EcdhPublicKeyResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.GeneralSecurityException;

@RestController
@RequestMapping("/crypto/server/ecdh")
public class EcdhCryptoController {

    private final EcdhCryptoService ecdhCryptoService;

    public EcdhCryptoController(EcdhCryptoService ecdhCryptoService) {
        this.ecdhCryptoService = ecdhCryptoService;
    }

    @GetMapping("/public-key")
    public EcdhPublicKeyResponse getEcdhPublicKey() throws GeneralSecurityException {
        return ecdhCryptoService.getPublicKey();
    }

}
