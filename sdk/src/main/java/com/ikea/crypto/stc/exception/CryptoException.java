package com.ikea.crypto.stc.exception;

/**
 * Base class for cryptographic errors.
 * <p>
 * This exception serves as the root for all cryptographic-related exceptions in the application.
 * It can be used to catch any cryptographic error, whether it is client-side or server-side.
 * </p>
 */
public class CryptoException extends RuntimeException {
    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
