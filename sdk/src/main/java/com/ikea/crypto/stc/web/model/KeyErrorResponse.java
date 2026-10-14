package com.ikea.crypto.stc.web.model;

/**
 * Represents the structure of an error response returned by the crypto service when a key-related error occurs.
 *
 * @param code The error code representing the type of key-related error.
 * @param message A brief message describing the key-related error.
 * @param data Additional data providing more context about the key-related error.
 */
public record KeyErrorResponse(
        String code,
        String message,
        Object data
) {
}
