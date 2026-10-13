package com.ikea.crypto.stc.web.advice;

import com.ikea.crypto.stc.annotation.DecryptRequest;
import com.ikea.crypto.stc.annotation.EncryptResponse;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.exception.InvalidCryptoRequestException;
import com.ikea.crypto.stc.model.SessionKeyHeaders;
import com.ikea.crypto.stc.session.CryptoSessionContext;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import com.ikea.crypto.stc.web.codec.CryptoPayloadHandler;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * A Spring ControllerAdvice that intercepts HTTP requests to decrypt the request body if annotated with @DecryptRequest
 * and sets up the cryptographic session context for further processing.
 */
@ControllerAdvice
@Slf4j
public class RequestDecryptAdvice implements RequestBodyAdvice {

    private final CryptoPayloadHandler payloadHandler;

    public RequestDecryptAdvice(CryptoPayloadHandler payloadHandler) {
        this.payloadHandler = payloadHandler;
    }

    @Override
    public boolean supports(MethodParameter methodParameter,
                            Type targetType,
                            Class<? extends HttpMessageConverter<?>> converterType) {
        return findDecryptRequest(methodParameter) != null || findEncryptResponse(methodParameter) != null;
    }

    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage inputMessage,
                                         MethodParameter parameter,
                                         Type targetType,
                                         Class<? extends HttpMessageConverter<?>> converterType)
            throws IOException {
        log.debug("【api pre-called】start to decrypting request body");
        boolean decryptRequest = findDecryptRequest(parameter) != null;
        boolean encryptResponse = findEncryptResponse(parameter) != null;
        if (!decryptRequest && !encryptResponse) {
            return inputMessage;
        }
        SessionKeyHeaders sessionKeyHeaders = sessionKeyHeaders(inputMessage.getHeaders());

        try {
            CryptoSessionContext sessionContext;
            if (decryptRequest) {
                String encryptedBody = new String(inputMessage.getBody().readAllBytes(), StandardCharsets.UTF_8);
                sessionContext = payloadHandler.createSessionContext(encryptedBody, sessionKeyHeaders);
                String decryptedBody = payloadHandler.decrypt(sessionContext);
                CryptoSessionContextAccessor.setCryptoSessionContext(sessionContext);
                return new HttpInputMessage() {
                    @Override
                    public InputStream getBody() {
                        return new ByteArrayInputStream(decryptedBody.getBytes(StandardCharsets.UTF_8));
                    }

                    @Override
                    public HttpHeaders getHeaders() {
                        return inputMessage.getHeaders();
                    }
                };
            }
            sessionContext = payloadHandler.createResponseSessionContext(sessionKeyHeaders);
            CryptoSessionContextAccessor.setCryptoSessionContext(sessionContext);
            return inputMessage;
        } catch (GeneralSecurityException e) {
            throw new InvalidCryptoRequestException("Failed to decrypt request body", e);
        }
    }

    @Override
    public Object afterBodyRead(Object body,
                                HttpInputMessage inputMessage,
                                MethodParameter parameter,
                                Type targetType,
                                Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }

    @Override
    public Object handleEmptyBody(Object body,
                                  HttpInputMessage inputMessage,
                                  MethodParameter parameter,
                                  Type targetType,
                                  Class<? extends HttpMessageConverter<?>> converterType) {
        if (findDecryptRequest(parameter) == null && findEncryptResponse(parameter) != null) {
            CryptoSessionContextAccessor.setCryptoSessionContext(
                    payloadHandler.createResponseSessionContext(sessionKeyHeaders(inputMessage.getHeaders())));
        }
        return body;
    }

    private SessionKeyHeaders sessionKeyHeaders(HttpHeaders headers) {
        return new SessionKeyHeaders(
                headers.getFirst(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_KEY_ID),
                headers.getFirst(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_SESSION_KEY));
    }

    private DecryptRequest findDecryptRequest(MethodParameter methodParameter) {
        return CryptoAdviceSupport.findAnnotation(methodParameter, DecryptRequest.class);
    }

    private EncryptResponse findEncryptResponse(MethodParameter methodParameter) {
        return CryptoAdviceSupport.findAnnotation(methodParameter, EncryptResponse.class);
    }
}
