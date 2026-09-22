package com.example.demo.server.crypto;

import com.example.demo.crypto.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.security.GeneralSecurityException;


@RestController
@RequestMapping("/api/crypto")
public class HybridCryptoController {

    private final HybridCryptoServer cryptoServer;

    public HybridCryptoController(HybridCryptoServer cryptoServer) {
        this.cryptoServer = cryptoServer;
    }

    @GetMapping("/public-key")
    public PublicKeyResponse getPublicKey(@RequestParam(defaultValue = CryptoConstants.ALGORITHM_RSA) String algorithm) {
        if (CryptoConstants.ALGORITHM_ECDH.equalsIgnoreCase(algorithm)) {
            return new PublicKeyResponse(
                    CryptoConstants.ALGORITHM_ECDH,
                    CryptoConstants.CURVE_ECDH,
                    EncodingUtils.toBase64(cryptoServer.ecdhPublicKey().getEncoded())
            );
        }
        return new PublicKeyResponse(
                CryptoConstants.ALGORITHM_RSA,
                null,
                EncodingUtils.toBase64(cryptoServer.rsaPublicKey().getEncoded())
        );
    }

    @PostMapping("/decrypt-data")
    public DecryptDataResponse decryptData(@RequestBody HybridCipherPayload payload) throws GeneralSecurityException {
        return new DecryptDataResponse(cryptoServer.decryptData(payload));
    }


    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(GeneralSecurityException.class)
    public ErrorResponse handleGeneralSecurityException() {
        return new ErrorResponse("Invalid encrypted payload");
    }
}
