package com.ikea.crypto.server.model;

public record KeyErrorResponse(
        String code,
        String msg,
        Object data
) {
}
