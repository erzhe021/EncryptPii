package com.ikea.crypto.stc.web.advice;

import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.exception.CryptoClientSideException;
import com.ikea.crypto.stc.exception.CryptoServerSideException;
import com.ikea.crypto.stc.exception.InvalidKeyException;
import com.ikea.crypto.stc.exception.KeyExpiredException;
import com.ikea.crypto.stc.web.model.CryptoErrorResponse;
import com.ikea.crypto.stc.web.model.KeyErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
@Slf4j
public class CryptoExceptionHandler {

    @ExceptionHandler(KeyExpiredException.class)
    public ResponseEntity<KeyErrorResponse> handleExpiredKey(KeyExpiredException exception) {
        log.warn("Rejected request using an expired key version");
        HttpHeaders headers = plainCryptoHeaders();
        headers.setCacheControl("no-store");
        KeyErrorResponse body = new KeyErrorResponse(
                CryptoConstants.KEY_EXPIRED_CODE,
                "The key version has expired; please update to the new version specified in the 'data' field.",
                exception.latestKey()
        );
        return new ResponseEntity<>(body, headers, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(InvalidKeyException.class)
    public ResponseEntity<KeyErrorResponse> handleInvalidKey(InvalidKeyException exception) {
        log.warn("Rejected request using an invalid key alias");
        HttpHeaders headers = plainCryptoHeaders();
        headers.setCacheControl("no-store");
        KeyErrorResponse body = new KeyErrorResponse(CryptoConstants.INVALID_KEY_CODE, "Invalid key", null);
        return new ResponseEntity<>(body, headers, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(CryptoClientSideException.class)
    public ResponseEntity<CryptoErrorResponse> handleCryptoClientError(
            CryptoClientSideException exception, WebRequest request) {
        log.warn("Crypto client-side request error: {}", exception.getMessage());
        return errorResponse(exception.getMessage(), HttpStatus.BAD_REQUEST, request);
    }

    @ExceptionHandler(CryptoServerSideException.class)
    public ResponseEntity<CryptoErrorResponse> handleCryptoServerError(
            CryptoServerSideException exception, WebRequest request) {
        log.error("Crypto server-side internal error", exception);
        return errorResponse("Cryptographic service internal error", HttpStatus.INTERNAL_SERVER_ERROR, request);
    }

    private ResponseEntity<CryptoErrorResponse> errorResponse(
            String message, HttpStatus status, WebRequest request) {
        CryptoErrorResponse body = new CryptoErrorResponse(
                System.currentTimeMillis(),
                status.value(),
                status.getReasonPhrase(),
                message,
                getPath(request)
        );
        return ResponseEntity.status(status)
                .headers(plainCryptoHeaders())
                .body(body);
    }

    private HttpHeaders plainCryptoHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_ENCRYPTED, "false");
        return headers;
    }

    private String getPath(WebRequest request) {
        String description = request.getDescription(false);
        return description.startsWith("uri=") ? description.substring(4) : description;
    }
}
