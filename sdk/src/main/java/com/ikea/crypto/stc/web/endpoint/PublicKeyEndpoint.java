package com.ikea.crypto.stc.web.endpoint;

import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.model.PublicKeyResponse;
import com.ikea.crypto.stc.model.RotateKeyRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * PublicKeyEndpoint provides REST endpoints for managing RSA public keys.
 * <p>
 * Endpoints:
 * - GET /public-key: Retrieve the current RSA public key.
 * - GET /public-key/{keyAlias}: Retrieve the RSA public key for a specific key alias.
 * - POST /rotate: Rotate the RSA key pair.
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

    @PostMapping("/rotate")
    public PublicKeyResponse rotateKey(
            @RequestParam(value = "keyAlias", required = false) String keyAlias,
            @RequestBody(required = false) RotateKeyRequest request) {
        String targetKeyAlias = request != null && request.keyAlias() != null
                ? request.keyAlias() : keyAlias;
        return rotateKey(targetKeyAlias, request != null && request.force());
    }

    @PostMapping("/rotate/{keyAlias}")
    public PublicKeyResponse rotateKey(@PathVariable("keyAlias") String keyAlias) {
        return rotateKey(keyAlias, false);
    }

    private PublicKeyResponse rotateKey(String keyAlias, boolean force) {
        return force ? cryptoServer.forceRotateKey(keyAlias) : cryptoServer.rotateKey(keyAlias);
    }
}
