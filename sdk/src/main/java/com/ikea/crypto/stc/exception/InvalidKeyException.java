package com.ikea.crypto.stc.exception;

public class InvalidKeyException extends CryptoClientSideException {
    public InvalidKeyException() {
        super("Invalid key");
    }
}
