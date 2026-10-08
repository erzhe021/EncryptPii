package com.ikea.crypto.stc.web.advice;

import com.ikea.crypto.stc.annotation.DecryptRequest;
import com.ikea.crypto.stc.annotation.EncryptResponse;
import com.ikea.crypto.stc.exception.InvalidCryptoPayloadException;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.model.SessionKeyTransport;
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
        String keyId = inputMessage.getHeaders().getFirst(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_KEY_ID);
        String encryptedSessionKey = inputMessage.getHeaders()
                .getFirst(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_SESSION_KEY);
        try {
            CryptoSessionContext sessionContext;
            if (decryptRequest) {
                String encryptedBody = new String(inputMessage.getBody().readAllBytes(), StandardCharsets.UTF_8);
                sessionContext = payloadHandler.createSessionContext(encryptedBody, keyId, encryptedSessionKey);
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
            if (keyId == null || keyId.isBlank() || encryptedSessionKey == null || encryptedSessionKey.isBlank()) {
                throw new InvalidCryptoPayloadException(
                        "X-STC-Key-Id and X-STC-Session-Key are required; body key transport is unsupported");
            }
            sessionContext = CryptoSessionContext.responseOnly(new SessionKeyTransport(keyId, encryptedSessionKey));
            CryptoSessionContextAccessor.setCryptoSessionContext(sessionContext);
            return inputMessage;
        } catch (GeneralSecurityException e) {
            throw new InvalidCryptoPayloadException("Failed to decrypt request body", e);
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
            String keyId = inputMessage.getHeaders().getFirst(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_KEY_ID);
            String encryptedSessionKey = inputMessage.getHeaders()
                    .getFirst(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_SESSION_KEY);
            if (keyId == null || keyId.isBlank() || encryptedSessionKey == null || encryptedSessionKey.isBlank()) {
                throw new InvalidCryptoPayloadException(
                        "X-STC-Key-Id and X-STC-Session-Key are required; body key transport is unsupported");
            }
            CryptoSessionContextAccessor.setCryptoSessionContext(
                    CryptoSessionContext.responseOnly(new SessionKeyTransport(keyId, encryptedSessionKey)));
        }
        return body;
    }

    private DecryptRequest findDecryptRequest(MethodParameter methodParameter) {
        return CryptoAdviceSupport.findAnnotation(methodParameter, DecryptRequest.class);
    }

    private EncryptResponse findEncryptResponse(MethodParameter methodParameter) {
        return CryptoAdviceSupport.findAnnotation(methodParameter, EncryptResponse.class);
    }
}
