package com.ikea.crypto.stc.web.model;

public record CryptoErrorResponse(
        Long timestamp,
        Integer status,
        String error,
        String message,
        String path
) {
}
