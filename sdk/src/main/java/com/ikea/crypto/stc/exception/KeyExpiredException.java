package com.ikea.crypto.stc.exception;

import com.ikea.crypto.stc.model.PublicKeyResponse;

import java.io.Serial;

/**
 * Thrown when the key version has expired.
 * This can occur when the key is no longer valid for cryptographic operations due to expiration or revocation.
 */
public class KeyExpiredException extends CryptoClientSideException {

    @Serial
    private static final long serialVersionUID = 1L;

    private final PublicKeyResponse latestKey;

    public KeyExpiredException(PublicKeyResponse latestKey) {
        super("The key version has expired");
        this.latestKey = latestKey;
    }

    public PublicKeyResponse latestKey() {
        return latestKey;
    }
}
