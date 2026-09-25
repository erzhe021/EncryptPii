package com.ikea.crypto.server.error;

public class InvalidCryptoPayloadException extends CryptoException {
    public InvalidCryptoPayloadException(String message) {
        super(message);
    }

    public InvalidCryptoPayloadException(String message, Throwable cause) {
        super(message, cause);
    }
}
