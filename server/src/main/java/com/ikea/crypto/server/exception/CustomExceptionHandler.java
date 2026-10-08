package com.ikea.crypto.server.exception;

import com.ikea.crypto.server.model.ErrorResult;
import com.ikea.crypto.server.model.Result;
import com.ikea.crypto.server.model.KeyErrorResponse;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.exception.CryptoClientSideException;
import com.ikea.crypto.stc.exception.CryptoException;
import com.ikea.crypto.stc.exception.InvalidKeyException;
import com.ikea.crypto.stc.exception.KeyExpiredException;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.TypeMismatchException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.multipart.support.MissingServletRequestPartException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.List;
import java.util.Set;
import java.security.GeneralSecurityException;

@RestControllerAdvice
@Slf4j
public class CustomExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(KeyExpiredException.class)
    public ResponseEntity<KeyErrorResponse> handleExpiredKey(KeyExpiredException exception) {
        log.warn("Rejected request using an expired key version");
        HttpHeaders headers = plainCryptoHeaders();
        headers.setCacheControl("no-store");
        KeyErrorResponse body = new KeyErrorResponse(CryptoConstants.KEY_EXPIRED_CODE,
                "The key version has expired; please update to the new version specified in the 'data' field.",
                exception.latestKey());
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
    public ResponseEntity<Object> handleCryptoClientError(CryptoClientSideException exception, WebRequest request) {
        log.warn("Crypto client-side request error: {}", exception.getMessage());
        ResponseEntity<Object> response = handleErrorResponse(
                exception.getMessage(), HttpStatus.BAD_REQUEST, getPath(request));
        return new ResponseEntity<>(response.getBody(), plainCryptoHeaders(), response.getStatusCode());
    }

    @ExceptionHandler({CryptoException.class, GeneralSecurityException.class})
    public ResponseEntity<Object> handleCryptoServerError(Exception exception, WebRequest request) {
        log.error("Crypto server-side internal error", exception);
        ResponseEntity<Object> response = handleErrorResponse(
                "Cryptographic service internal error", HttpStatus.INTERNAL_SERVER_ERROR, getPath(request));
        return new ResponseEntity<>(response.getBody(), plainCryptoHeaders(), response.getStatusCode());
    }

    // customized ExceptionHandler start ============>
    @ExceptionHandler({ConstraintViolationException.class})
    public ResponseEntity<Object> handleConstraintViolationException(
            ConstraintViolationException constraintViolationException, WebRequest request) {

        String errorMsg = "";
        String path = getPath(request);

        Set<ConstraintViolation<?>> violations = constraintViolationException.getConstraintViolations();
        if (!violations.isEmpty()) {
            ConstraintViolation<?> item = violations.iterator().next();
            errorMsg = item.getMessage();
            log.warn("ConstraintViolationException, request: {}, exception: {}, invalid value: {}",
                    path, errorMsg, item.getInvalidValue());
        }
        return handleErrorResponse(errorMsg, HttpStatus.BAD_REQUEST, path);
    }

    @ExceptionHandler({IllegalArgumentException.class})
    protected ResponseEntity<Object> handleIllegalArgument(IllegalArgumentException ex, WebRequest request) {
        String path = getPath(request);
        log.warn("IllegalArgumentException, request: {}, exception: {}", path, ex.getMessage());
        return handleErrorResponse(ex.getMessage(), HttpStatus.BAD_REQUEST, path);
    }

    @ExceptionHandler({BusinessException.class})
    public ResponseEntity<Object> handleBusinessException(
            BusinessException businessException, WebRequest request) {

        String path = getPath(request);
        Result<Void> body = Result.fail(businessException.getCode(), businessException.getMessage());
        log.warn("BusinessException, request: {}, exception: {}", path, businessException.getMessage());
        return ResponseEntity.ok().body(body);
    }

    @ExceptionHandler({SystemException.class})
    public ResponseEntity<Object> handleSystemException(SystemException systemException, WebRequest request) {

        String path = getPath(request);
        if (systemException.getCause() != null) {
            log.error("SystemException, request: {}, exception: {}, caused by:", path, systemException.getMessage(), systemException.getCause());
        } else {
            log.error("SystemException, request: {}, exception: {}", path, systemException.getMessage());
        }
        return handleErrorResponse(systemException.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR, path);
    }

    @ExceptionHandler({Exception.class})
    public ResponseEntity<Object> handleUnspecificException(Exception ex, WebRequest request) {

        String path = getPath(request);
        String errorMsg = ex.getMessage();
        log.error("Unspecific exception, request: {}, exception: {}", path, errorMsg, ex);
        return handleErrorResponse(errorMsg, HttpStatus.INTERNAL_SERVER_ERROR, path);
    }


    // Override ExceptionHandler start ============>
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
                                                                  HttpHeaders headers,
                                                                  HttpStatusCode status,
                                                                  WebRequest request) {
        String errorMsg = buildMessages(ex.getBindingResult());
        log.warn("MethodArgumentNotValidException, request: {}, exception: {}", getPath(request), errorMsg);
        return handleOverriddenException(ex, headers, status, request, errorMsg);
    }

    @Override
    protected ResponseEntity<Object> handleTypeMismatch(TypeMismatchException ex,
                                                        HttpHeaders headers,
                                                        HttpStatusCode status,
                                                        WebRequest request) {
        log.warn("TypeMismatchException, request: {}, exception: {}", getPath(request), ex.getMessage());
        return handleOverriddenException(ex, headers, status, request, ex.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestParameter(MissingServletRequestParameterException ex,
                                                                          HttpHeaders headers,
                                                                          HttpStatusCode status,
                                                                          WebRequest request) {
        log.warn("MissingServletRequestParameterException, request: {}, exception: {}",
                getPath(request), ex.getMessage());
        return handleOverriddenException(ex, headers, status, request, ex.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleMissingServletRequestPart(MissingServletRequestPartException ex,
                                                                     HttpHeaders headers,
                                                                     HttpStatusCode status,
                                                                     WebRequest request) {
        log.warn("MissingServletRequestPartException, request: {}, exception: {}", getPath(request), ex.getMessage());
        return handleOverriddenException(ex, headers, status, request, ex.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
                                                                  HttpHeaders headers,
                                                                  HttpStatusCode status,
                                                                  WebRequest request) {
        String errorMsg = ex.getMostSpecificCause().getMessage();

        log.warn("HttpMessageNotReadableException, request: {}, exception: {}", getPath(request), errorMsg);
        return handleOverriddenException(ex, headers, status, request, errorMsg);
    }

    @Override
    protected ResponseEntity<Object> handleServletRequestBindingException(ServletRequestBindingException ex,
                                                                          HttpHeaders headers,
                                                                          HttpStatusCode status,
                                                                          WebRequest request) {
        log.warn("ServletRequestBindingException, request: {}, exception: {}", getPath(request), ex.getMessage());
        return handleOverriddenException(ex, headers, status, request, ex.getMessage());
    }

    @Override
    protected ResponseEntity<Object> handleHttpRequestMethodNotSupported(HttpRequestMethodNotSupportedException ex,
                                                                         HttpHeaders headers,
                                                                         HttpStatusCode status,
                                                                         WebRequest request) {
        String errorMsg = ex.getMessage();
        log.warn("HttpRequestMethodNotSupportedException, request: {}, exception: {}", getPath(request), errorMsg);
        return handleOverriddenException(ex, headers, status, request, ex.getMessage());
    }

    // helper private method start ===>
    private HttpHeaders plainCryptoHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_ENCRYPTED, "false");
        return headers;
    }

    private String buildMessages(BindingResult result) {

        StringBuilder resultBuilder = new StringBuilder();
        List<ObjectError> errors = result.getAllErrors();
        for (ObjectError error : errors) {
            if (error instanceof FieldError fieldError) {
                String fieldName = fieldError.getField();
                String fieldErrMsg = fieldError.getDefaultMessage();
                resultBuilder.append(fieldName).append(" ").append(fieldErrMsg);
            }
        }
        return resultBuilder.toString();
    }

    private ResponseEntity<Object> handleErrorResponse(String errorMsg, HttpStatus httpStatus, String path) {

        ErrorResult body = ErrorResult.builder()
                .timestamp(System.currentTimeMillis())
                .status(httpStatus.value())
                .error(httpStatus.getReasonPhrase())
                .message(errorMsg)
                .path(path)
                .build();
        return ResponseEntity.status(httpStatus).body(body);
    }

    private ResponseEntity<Object> handleOverriddenException(
            Exception ex, HttpHeaders headers, HttpStatusCode status, WebRequest request, String errorMsg) {

        ErrorResult body = ErrorResult.builder()
                .timestamp(System.currentTimeMillis())
                .status(status.value())
                .error(status.toString())
                .message(errorMsg)
                .path(getPath(request))
                .build();
        return handleExceptionInternal(ex, body, headers, status, request);
    }

    private String getPath(WebRequest request) {
        String description = request.getDescription(false);
        return description.startsWith("uri=") ? description.substring(4) : description;
    }

}