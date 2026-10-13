package com.ikea.crypto.stc.exception;

/**
 * Thrown when the provided cryptographic key is invalid.
 * This can occur due to incorrect key format, unsupported key type, or mismatched key length.
 */
public class InvalidKeyException extends CryptoClientSideException {
    public InvalidKeyException() {
        super("Invalid key");
    }
}
