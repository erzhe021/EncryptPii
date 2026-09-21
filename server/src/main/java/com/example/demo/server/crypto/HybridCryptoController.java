package com.example.demo.server.crypto;

import com.example.demo.crypto.DecryptPhoneResponse;
import com.example.demo.crypto.HybridCipherPayload;
import com.example.demo.crypto.HybridCryptoServer;
import com.example.demo.crypto.PublicKeyResponse;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.security.GeneralSecurityException;

@RestController
@RequestMapping("/api/crypto")
public class HybridCryptoController {
    private final HybridCryptoServer cryptoServer;

    public HybridCryptoController(HybridCryptoServer cryptoServer) {
        this.cryptoServer = cryptoServer;
    }

    @GetMapping("/public-key")
    public PublicKeyResponse getPublicKey(
            @org.springframework.web.bind.annotation.RequestParam(defaultValue = "RSA") String algorithm
    ) {
        if ("ECDH".equalsIgnoreCase(algorithm)) {
            return new PublicKeyResponse(
                    "ECDH",
                    com.example.demo.crypto.CryptoConstants.ECDH_CURVE,
                    com.example.demo.crypto.EncodingUtils.toBase64(cryptoServer.ecdhPublicKey().getEncoded())
            );
        }
        return new PublicKeyResponse(
                "RSA",
                null,
                com.example.demo.crypto.EncodingUtils.toBase64(cryptoServer.rsaPublicKey().getEncoded())
        );
    }

    @PostMapping("/decrypt-phone")
    public DecryptPhoneResponse decryptPhone(@RequestBody HybridCipherPayload payload) throws GeneralSecurityException {
        return new DecryptPhoneResponse(cryptoServer.decryptPhone(payload));
    }

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(GeneralSecurityException.class)
    public ErrorResponse handleGeneralSecurityException() {
        return new ErrorResponse("Invalid encrypted payload");
    }
}
