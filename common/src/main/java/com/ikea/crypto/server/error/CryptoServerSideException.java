package com.ikea.crypto.server.error;

/**
 * Base class for server-side cryptographic errors (HTTP 5xx).
 * Indicates key store failure, Vault unavailability, or internal encryption/serialization error.
 */
public class CryptoServerSideException extends CryptoException {
    public CryptoServerSideException(String message) {
        super(message);
    }

    public CryptoServerSideException(String message, Throwable cause) {
        super(message, cause);
    }
}
