package com.ikea.crypto.stc.exception;

/**
 * Thrown when the client request payload is malformed (e.g. invalid JSON, missing required fields).
 */
public class InvalidCryptoPayloadException extends CryptoClientSideException {
    public InvalidCryptoPayloadException(String message) {
        super(message);
    }

    public InvalidCryptoPayloadException(String message, Throwable cause) {
        super(message, cause);
    }
}

