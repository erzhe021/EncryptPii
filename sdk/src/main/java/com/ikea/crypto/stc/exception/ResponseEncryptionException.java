package com.ikea.crypto.stc.exception;

/**
 * Thrown when encrypting or serializing the server response body fails.
 */
public class ResponseEncryptionException extends CryptoServerSideException {
    public ResponseEncryptionException(String message) {
        super(message);
    }

    public ResponseEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}

