package com.ikea.crypto.stc.exception;

import java.io.Serial;

/**
 * Base class for server-side cryptographic errors (HTTP 5xx).
 * Indicates key store failure, Vault unavailability, or internal encryption/serialization error.
 */
public class CryptoServerSideException extends CryptoException {

    @Serial
    private static final long serialVersionUID = 1L;

    public CryptoServerSideException(String message) {
        super(message);
    }

    public CryptoServerSideException(String message, Throwable cause) {
        super(message, cause);
    }
}
