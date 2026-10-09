package com.ikea.crypto.stc.web.model;

public record KeyErrorResponse(
        String code,
        String msg,
        Object data
) {
}
