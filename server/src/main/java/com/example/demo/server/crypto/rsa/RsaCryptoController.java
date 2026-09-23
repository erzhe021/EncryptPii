package com.example.demo.server.crypto.rsa;

import com.example.demo.crypto.rsa.RsaPublicKeyResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/crypto/server/rsa")
public class RsaCryptoController {

    private final RsaCryptoService rsaCryptoService;

    public RsaCryptoController(RsaCryptoService rsaCryptoService) {
        this.rsaCryptoService = rsaCryptoService;
    }

    @GetMapping("/public-key")
    public RsaPublicKeyResponse getRsaPublicKey() {
        return rsaCryptoService.getPublicKey();
    }

}
