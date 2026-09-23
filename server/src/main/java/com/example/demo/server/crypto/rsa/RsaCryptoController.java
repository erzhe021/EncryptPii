package com.example.demo.server.crypto.rsa;

import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.crypto.rsa.RsaDecryptDataResponse;
import com.example.demo.crypto.rsa.RsaPublicKeyResponse;
import com.example.demo.server.crypto.ErrorResponse;
import org.springframework.http.HttpStatus;
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

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(GeneralSecurityException.class)
    public ErrorResponse handleGeneralSecurityException() {
        return new ErrorResponse("Invalid encrypted payload");
    }
}
