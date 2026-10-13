package com.ikea.crypto.stc.exception;

/**
 * Thrown when the request to the cryptographic service is invalid.
 * This can occur due to malformed request payloads, unsupported operations, or missing required parameters.
 */
public class InvalidCryptoRequestException extends CryptoClientSideException {

    public InvalidCryptoRequestException(String message) {
        super(message);
    }

    public InvalidCryptoRequestException(String message, Throwable cause) {
        super(message, cause);
    }

}

