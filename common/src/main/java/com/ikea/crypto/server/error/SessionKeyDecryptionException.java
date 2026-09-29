package com.ikea.crypto.server.error;

/**
 * Thrown when session key decryption fails (e.g. invalid RSA ciphertext, expired/unknown keyId,
 * or mismatched private key).
 */
public class SessionKeyDecryptionException extends CryptoClientSideException {
    public SessionKeyDecryptionException(String message) {
        super(message);
    }

    public SessionKeyDecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
