package com.ikea.crypto.server.error;

/**
 * Thrown when symmetric decryption fails (e.g. GCM authentication tag mismatch, indicating
 * the ciphertext was tampered with or corrupted).
 */
public class DataTamperedException extends CryptoClientSideException {
    public DataTamperedException(String message) {
        super(message);
    }

    public DataTamperedException(String message, Throwable cause) {
        super(message, cause);
    }
}
