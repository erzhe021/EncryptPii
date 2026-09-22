package com.example.demo.server.crypto;

import com.example.demo.crypto.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.security.GeneralSecurityException;

@RestController
@RequestMapping("/api/crypto")
public class HybridCryptoController {

    private final RsaCryptoService rsaCryptoService;
    private final EcdhCryptoService ecdhCryptoService;

    public HybridCryptoController(RsaCryptoService rsaCryptoService, EcdhCryptoService ecdhCryptoService) {
        this.rsaCryptoService = rsaCryptoService;
        this.ecdhCryptoService = ecdhCryptoService;
    }

    @GetMapping("/rsa/public-key")
    public RsaPublicKeyResponse getRsaPublicKey() {
        return rsaCryptoService.getPublicKey();
    }

    @PostMapping("/rsa/decrypt")
    public RsaDecryptDataResponse decryptRsa(@RequestBody RsaHybridCipherPayload payload) throws GeneralSecurityException {
        return new RsaDecryptDataResponse(rsaCryptoService.decrypt(payload));
    }

    @GetMapping("/ecdh/public-key")
    public EcdhPublicKeyResponse getEcdhPublicKey() throws GeneralSecurityException {
        return ecdhCryptoService.getPublicKey();
    }

    @PostMapping("/ecdh/decrypt")
    public EcdhDecryptDataResponse decryptEcdh(@RequestBody EcdhHybridCipherPayload payload) throws GeneralSecurityException {
        return new EcdhDecryptDataResponse(ecdhCryptoService.decrypt(payload));
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(GeneralSecurityException.class)
    public ErrorResponse handleGeneralSecurityException() {
        return new ErrorResponse("Invalid encrypted payload");
    }
}
