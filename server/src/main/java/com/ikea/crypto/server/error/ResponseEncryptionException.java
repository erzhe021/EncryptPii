package com.ikea.crypto.server.error;

public class ResponseEncryptionException extends CryptoException {
    public ResponseEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
