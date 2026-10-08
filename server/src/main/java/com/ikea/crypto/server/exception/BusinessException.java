package com.ikea.crypto.server.exception;

import lombok.Getter;

import java.io.Serial;

public class BusinessException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 7426845416694457839L;

    @Getter
    private final String code;

    @Getter
    private final String message;

    public BusinessException(String code, String message) {
        this.code = code;
        this.message = message;
    }

}
