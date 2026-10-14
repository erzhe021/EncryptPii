package com.ikea.crypto.stc.exception;

import java.io.Serial;

/**
 * Exception thrown when there is an error during the encryption of a response.
 * This exception indicates that the server encountered an issue while attempting to encrypt the response data.
 */
public class ResponseEncryptionException extends CryptoServerSideException {

    @Serial
    private static final long serialVersionUID = 1L;

    public ResponseEncryptionException(String message) {
        super(message);
    }

    public ResponseEncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
