package com.ikea.crypto.stc.exception;

/**
 * Thrown when the cryptographic key or key storage is unavailable on the server side
 * (e.g. Vault connection failure, empty keyring, or active key not found).
 */
public class KeyNotAvailableException extends CryptoServerSideException {
    public KeyNotAvailableException(String message) {
        super(message);
    }

    public KeyNotAvailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
