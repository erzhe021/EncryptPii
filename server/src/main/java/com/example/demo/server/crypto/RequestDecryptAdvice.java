package com.example.demo.server.crypto;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

@ControllerAdvice
public class RequestDecryptAdvice implements RequestBodyAdvice {

    private final CryptoPayloadHandlerRegistry handlerRegistry;

    public RequestDecryptAdvice(CryptoPayloadHandlerRegistry handlerRegistry) {
        this.handlerRegistry = handlerRegistry;
    }

    @Override
    public boolean supports(MethodParameter methodParameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return findDecryptRequest(methodParameter) != null;
    }

    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage inputMessage, MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) throws IOException {
        DecryptRequest decryptRequest = findDecryptRequest(parameter);
        if (decryptRequest == null) {
            return inputMessage;
        }
        String encryptedBody = new String(inputMessage.getBody().readAllBytes(), StandardCharsets.UTF_8);
        String plainJson;
        try {
            CryptoPayloadHandler handler = handlerRegistry.getRequiredHandler(decryptRequest.value());
            CryptoSessionContext sessionContext = handler.createSessionContext(encryptedBody);
            RequestContextHolder.currentRequestAttributes()
                    .setAttribute(CryptoSessionContext.REQUEST_CONTEXT_KEY, sessionContext, RequestAttributes.SCOPE_REQUEST);
            plainJson = handler.decrypt(encryptedBody, targetType);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Failed to decrypt request body", e);
        }

        return new HttpInputMessage() {
            @Override
            public InputStream getBody() {
                return new ByteArrayInputStream(plainJson.getBytes(StandardCharsets.UTF_8));
            }

            @Override
            public HttpHeaders getHeaders() {
                return inputMessage.getHeaders();
            }
        };
    }

    @Override
    public Object afterBodyRead(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }

    @Override
    public Object handleEmptyBody(Object body, HttpInputMessage inputMessage, MethodParameter parameter, Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }

    private DecryptRequest findDecryptRequest(MethodParameter methodParameter) {
        DecryptRequest annotation = methodParameter.getMethodAnnotation(DecryptRequest.class);
        if (annotation != null) {
            return annotation;
        }
        return AnnotatedElementUtils.findMergedAnnotation(methodParameter.getContainingClass(), DecryptRequest.class);
    }
}
