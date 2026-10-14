package com.ikea.crypto.stc.exception;

import java.io.Serial;

/**
 * Thrown when the provided cryptographic key is invalid.
 * This can occur due to incorrect key format, unsupported key type, or mismatched key length.
 */
public class InvalidKeyException extends CryptoClientSideException {

    @Serial
    private static final long serialVersionUID = 1L;

    public InvalidKeyException() {
        super("Invalid key");
    }
}
