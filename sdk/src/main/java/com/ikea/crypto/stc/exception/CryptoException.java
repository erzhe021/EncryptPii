package com.ikea.crypto.stc.exception;

import java.io.Serial;

/**
 * Base class for cryptographic errors.
 * <p>
 * This exception serves as the root for all cryptographic-related exceptions in the application.
 * It can be used to catch any cryptographic error, whether it is client-side or server-side.
 * </p>
 */
public abstract class CryptoException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    protected CryptoException(String message) {
        super(message);
    }

    protected CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
