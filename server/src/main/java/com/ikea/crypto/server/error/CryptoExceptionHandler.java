package com.ikea.crypto.server.error;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class CryptoExceptionHandler {

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler({IllegalArgumentException.class, InvalidCryptoPayloadException.class})
    public ErrorResponse handleBadRequest(RuntimeException exception) {
        return new ErrorResponse(exception.getMessage());
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler({CryptoException.class, ResponseEncryptionException.class})
    public ErrorResponse handleCryptoFailure(RuntimeException exception) {
        return new ErrorResponse(exception.getMessage());
    }
}
