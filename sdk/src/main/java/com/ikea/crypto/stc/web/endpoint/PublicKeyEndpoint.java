package com.ikea.crypto.stc.web.endpoint;

import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.model.PublicKeyResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for retrieving RSA public keys.
 * This endpoint provides access to the public keys used for cryptographic operations.
 */
@RestController
@RequestMapping("${sensitive.transport.crypto.endpoint.base-path:/sensitive-transport-crypto}")
@Slf4j
public class PublicKeyEndpoint {

    private final CryptoServer cryptoServer;

    public PublicKeyEndpoint(CryptoServer cryptoServer) {
        this.cryptoServer = cryptoServer;
    }

    @GetMapping("/public-key")
    public PublicKeyResponse getPublicKey() {
        log.debug("【api called】start to retrieving RSA public key");
        return cryptoServer.getPublicKey();
    }

    @GetMapping("/public-key/{keyAlias}")
    public PublicKeyResponse getPublicKey(@PathVariable("keyAlias") String keyAlias) {
        log.debug("【api called】start to retrieving RSA public key for keyAlias: {}", keyAlias);
        return cryptoServer.getPublicKey(keyAlias);
    }

}
