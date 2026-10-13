package com.ikea.crypto.stc.exception;

/**
 * Thrown when the response from the cryptographic service cannot be decrypted or is otherwise invalid.
 * This can occur due to issues with the encryption process, corrupted data, or mismatched keys.
 */
public class ResponseEncryptionException extends CryptoServerSideException {
    public ResponseEncryptionException(String message) {
        super(message);
    }

    public ResponseEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}

