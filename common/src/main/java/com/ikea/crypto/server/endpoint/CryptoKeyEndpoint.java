package com.ikea.crypto.server.endpoint;

import com.ikea.crypto.common.model.PublicKeyResponse;
import com.ikea.crypto.common.model.RotateKeyRequest;
import com.ikea.crypto.server.service.CryptoServer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

/**
 * CryptoKeyEndpoint provides REST endpoints for retrieving the RSA public key and rotating the RSA key pair.
 * <p>
 * Endpoints:
 * - GET /public-key: Retrieve the current RSA public key.
 * - GET /public-key/{keyAlias}: Retrieve the RSA public key for a specific key alias.
 * - POST /rotate-key: Rotate the RSA key pair, optionally specifying a key alias and force rotation.
 */
@RestController
@RequestMapping("${crypto.server.endpoint.base-path:/crypto/server}")
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

    /**
     * Rotate the RSA key pair.
     * <p>
     * If a key alias is provided in the request body, the rotation will be performed for that specific key alias.
     * If the 'force' flag is set to true, the rotation will be forced regardless of any existing conditions.
     *
     * This endpoint is intended for internal use only.
     * Consider adding authentication/authorization checks or moving it to a separate internal controller.
     *
     * @param requestBody Optional request body containing 'keyAlias' and 'force' parameters.
     * @return The new public key after rotation.
     */
    @PostMapping(value = {"/rotate", "/rotate-key", "/rotate/{keyAlias}", "/internal-use/rotate-key"})
    public PublicKeyResponse rotateKey(
            @PathVariable(value = "keyAlias", required = false) String pathKeyAlias,
            @RequestParam(value = "keyAlias", required = false) String paramKeyAlias,
            @RequestBody(required = false) RotateKeyRequest requestBody) {
        String keyAlias = null;
        boolean force = false;
        if (pathKeyAlias != null && !pathKeyAlias.isBlank()) {
            keyAlias = pathKeyAlias;
        } else if (paramKeyAlias != null && !paramKeyAlias.isBlank()) {
            keyAlias = paramKeyAlias;
        } else if (requestBody != null) {
            keyAlias = requestBody.keyAlias();
            force = Boolean.TRUE.equals(requestBody.force());
        }
        log.info("【api called】start to rotating RSA key, resolved keyAlias: {}, force: {}", keyAlias, force);
        if (force) {
            return cryptoServer.forceRotateKey(keyAlias);
        }
        return cryptoServer.rotateKey(keyAlias);
    }
}
