package com.ikea.crypto.stc.exception;

import java.io.Serial;

/**
 * Thrown when the decryption of a session key fails.
 * This can occur due to incorrect key usage, corrupted ciphertext, or other cryptographic issues.
 */
public class SessionKeyDecryptionException extends CryptoClientSideException {

    @Serial
    private static final long serialVersionUID = 1L;

    public SessionKeyDecryptionException(String message) {
        super(message);
    }

    public SessionKeyDecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
