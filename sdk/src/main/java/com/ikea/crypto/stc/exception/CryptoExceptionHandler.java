package com.ikea.crypto.stc.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.security.GeneralSecurityException;

/**
 * Optional fallback global exception handler for cryptographic operations.
 * Annotated with {@link Order} set to {@link Ordered#LOWEST_PRECEDENCE} so that
 * business applications' custom exception handlers take precedence.
 */
@Slf4j
@RestControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE)
public class CryptoExceptionHandler {

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler({CryptoClientSideException.class, IllegalArgumentException.class})
    public ErrorResponse handleClientSideError(RuntimeException exception) {
        log.warn("Crypto client-side request error: {}", exception.getMessage());
        return new ErrorResponse(exception.getMessage());
    }

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler({CryptoServerSideException.class, CryptoException.class, GeneralSecurityException.class})
    public ErrorResponse handleServerSideError(RuntimeException exception) {
        log.error("Crypto server-side internal error: {}", exception.getMessage(), exception);
        return new ErrorResponse("Cryptographic service internal error");
    }
}

