package com.ikea.crypto.stc.exception;

/**
 * Thrown when the requested cryptographic key is not available.
 * This can occur when the key has been deleted, is not yet generated, or is otherwise inaccessible.
 */
public class KeyNotAvailableException extends CryptoServerSideException {
    public KeyNotAvailableException(String message) {
        super(message);
    }

    public KeyNotAvailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
