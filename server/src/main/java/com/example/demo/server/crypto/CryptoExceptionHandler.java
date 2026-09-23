package com.example.demo.server.crypto;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class CryptoExceptionHandler {

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler({IllegalArgumentException.class, ResponseEncryptionException.class})
    public ErrorResponse handleCryptoException(RuntimeException exception) {
        return new ErrorResponse(exception.getMessage());
    }
}
