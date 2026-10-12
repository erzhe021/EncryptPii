package com.ikea.crypto.stc.exception;

/**
 * Thrown when the client request payload is malformed (e.g. invalid JSON, missing required fields).
 */
public class InvalidCryptoRequestException extends CryptoClientSideException {

    public InvalidCryptoRequestException(String message) {
        super(message);
    }

    public InvalidCryptoRequestException(String message, Throwable cause) {
        super(message, cause);
    }

}

