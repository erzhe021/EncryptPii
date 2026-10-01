package com.ikea.crypto.stc.web.endpoint;

import com.ikea.crypto.stc.model.EphemeralKeyResponse;
import com.ikea.crypto.stc.model.VerificationKeyResponse;
import com.ikea.crypto.stc.key.CryptoServer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.GeneralSecurityException;

@RestController
@RequestMapping("${sensitive.transport.crypto.endpoint.base-path:/crypto/server/ecdh}")
@Slf4j
public class CryptoKeyEndpoint {

    private final CryptoServer cryptoServer;

    public CryptoKeyEndpoint(CryptoServer cryptoServer) {
        this.cryptoServer = cryptoServer;
    }

    @GetMapping("/ephemeral-public-key")
    public EphemeralKeyResponse getEphemeralPublicKey() throws GeneralSecurityException {
        return cryptoServer.getEphemeralPublicKey();
    }

    @GetMapping("/ecdsa-public-key")
    public VerificationKeyResponse getEcdsaPublicKey() {
        return cryptoServer.getEcdsaPublicKey();
    }
}
