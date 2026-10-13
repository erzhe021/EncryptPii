package com.ikea.crypto.stc.web.model;

/**
 * Represents the structure of an error response returned by the crypto service.
 *
 * @param timestamp The timestamp when the error occurred.
 * @param status    The HTTP status code associated with the error.
 * @param error     A brief description of the error.
 * @param message   A detailed message providing more context about the error.
 * @param path      The request path that resulted in the error.
 */
public record CryptoErrorResponse(
        Long timestamp,
        Integer status,
        String error,
        String message,
        String path
) {
}
