package com.ikea.crypto.stc.exception;

/**
 * Base class for client-side cryptographic errors (HTTP 4xx).
 * Indicates bad request payload, invalid encoding, unknown keyId or data tampering.
 */
public class CryptoClientSideException extends CryptoException {
    public CryptoClientSideException(String message) {
        super(message);
    }

    public CryptoClientSideException(String message, Throwable cause) {
        super(message, cause);
    }
}
