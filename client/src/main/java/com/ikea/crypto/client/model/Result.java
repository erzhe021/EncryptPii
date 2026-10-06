package com.ikea.crypto.client.model;

import lombok.*;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
@ToString
public final class Result<T> {

    private String code;

    private String message;

    private T data;

    public static final String SUCCESS_CODE = "0";

    private static final Result<Void> SUCCESS_NO_DATA = ok(null);

    public static Result<Void> ok() {
        return SUCCESS_NO_DATA;
    }

    public static <T> Result<T> ok(T data) {
        return new Result<>(SUCCESS_CODE, null, data);
    }

    public static <T> Result<T> ok(String message, T data) {
        return new Result<>(SUCCESS_CODE, message, data);
    }

    public static <T> Result<T> fail(String code, String message) {
        return new Result<>(code, message, null);
    }
}
