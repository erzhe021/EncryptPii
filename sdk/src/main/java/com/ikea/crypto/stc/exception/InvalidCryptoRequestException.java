package com.ikea.crypto.stc.exception;

/**
 * Thrown when the request to the cryptographic service is invalid.
 * Used for malformed client payloads, invalid encodings, or missing required request fields.
 * Internal state, key store, and cryptographic initialization failures are server-side errors.
 */
public class InvalidCryptoRequestException extends CryptoClientSideException {

    public InvalidCryptoRequestException(String message) {
        super(message);
    }

    public InvalidCryptoRequestException(String message, Throwable cause) {
        super(message, cause);
    }

}
