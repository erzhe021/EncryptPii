package com.ikea.crypto.stc.exception;

import java.io.Serial;

/**
 * Thrown when the request to the cryptographic service is invalid.
 * Used for malformed client payloads, invalid encodings, or missing required request fields.
 * Internal state, key store, and cryptographic initialization failures are server-side errors.
 */
public class InvalidCryptoRequestException extends CryptoClientSideException {

    @Serial
    private static final long serialVersionUID = 1L;

    public InvalidCryptoRequestException(String message) {
        super(message);
    }

    public InvalidCryptoRequestException(String message, Throwable cause) {
        super(message, cause);
    }

}
