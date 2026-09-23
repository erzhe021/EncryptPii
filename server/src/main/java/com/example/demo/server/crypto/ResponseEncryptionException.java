package com.example.demo.server.crypto;

public class ResponseEncryptionException extends RuntimeException {
    public ResponseEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
