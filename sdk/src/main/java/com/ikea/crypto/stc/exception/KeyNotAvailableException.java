package com.ikea.crypto.stc.exception;

import java.io.Serial;

/**
 * Thrown when the requested cryptographic key is not available.
 * This can occur when the key has been deleted, is not yet generated, or is otherwise inaccessible.
 */
public class KeyNotAvailableException extends CryptoServerSideException {

    @Serial
    private static final long serialVersionUID = 1L;

    public KeyNotAvailableException(String message) {
        super(message);
    }

    public KeyNotAvailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
