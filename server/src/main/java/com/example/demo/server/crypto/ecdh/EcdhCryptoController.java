package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.ecdh.EcdhDecryptDataResponse;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhPublicKeyResponse;
import com.example.demo.server.crypto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.security.GeneralSecurityException;

@RestController
@RequestMapping("/api/crypto")
public class EcdhCryptoController {

    private final EcdhCryptoService ecdhCryptoService;

    public EcdhCryptoController(EcdhCryptoService ecdhCryptoService) {
        this.ecdhCryptoService = ecdhCryptoService;
    }

    @GetMapping("/ecdh/public-key")
    public EcdhPublicKeyResponse getEcdhPublicKey() throws GeneralSecurityException {
        return ecdhCryptoService.getPublicKey();
    }

    @PostMapping("/ecdh/decrypt")
    public EcdhDecryptDataResponse decryptEcdh(@RequestBody EcdhCipherPayload payload) throws GeneralSecurityException {
        return new EcdhDecryptDataResponse(ecdhCryptoService.decrypt(payload));
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(GeneralSecurityException.class)
    public ErrorResponse handleGeneralSecurityException() {
        return new ErrorResponse("Invalid encrypted payload");
    }
}
