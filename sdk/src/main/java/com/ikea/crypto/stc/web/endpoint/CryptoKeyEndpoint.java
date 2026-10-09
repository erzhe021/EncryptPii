package com.ikea.crypto.stc.web.endpoint;

import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.model.PublicKeyResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * CryptoKeyEndpoint provides REST endpoints for retrieving the RSA public key and rotating the RSA key pair.
 * <p>
 * Endpoints:
 * - GET /public-key: Retrieve the current RSA public key.
 * - GET /public-key/{keyAlias}: Retrieve the RSA public key for a specific key alias.
 */
@RestController
@RequestMapping("${sensitive.transport.crypto.endpoint.base-path:/crypto/server}")
@Slf4j
public class CryptoKeyEndpoint {

    private final CryptoServer cryptoServer;

    public CryptoKeyEndpoint(CryptoServer cryptoServer) {
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
