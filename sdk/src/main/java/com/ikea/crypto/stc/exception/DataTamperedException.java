package com.ikea.crypto.stc.exception;

import java.io.Serial;

/**
 * Thrown when symmetric decryption fails (e.g. GCM authentication tag mismatch, indicating
 * the ciphertext was tampered with or corrupted).
 */
public class DataTamperedException extends CryptoClientSideException {

    @Serial
    private static final long serialVersionUID = 1L;

    public DataTamperedException(String message) {
        super(message);
    }

    public DataTamperedException(String message, Throwable cause) {
        super(message, cause);
    }
}
