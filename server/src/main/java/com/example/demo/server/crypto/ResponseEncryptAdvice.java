package com.example.demo.server.crypto;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.security.GeneralSecurityException;

@ControllerAdvice
public class ResponseEncryptAdvice implements ResponseBodyAdvice<Object> {

    private final CryptoPayloadHandlerRegistry handlerRegistry;

    public ResponseEncryptAdvice(CryptoPayloadHandlerRegistry handlerRegistry) {
        this.handlerRegistry = handlerRegistry;
    }

    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        return findEncryptResponse(returnType) != null;
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType, Class<? extends HttpMessageConverter<?>> selectedConverterType, ServerHttpRequest request, ServerHttpResponse response) {
        EncryptResponse encryptResponse = findEncryptResponse(returnType);
        if (encryptResponse == null || body == null) {
            return body;
        }
        try {
            CryptoSessionContext sessionContext = getSessionContext();
            if (sessionContext == null) {
                throw new IllegalStateException("No request session context available for response encryption");
            }
            return handlerRegistry.getRequiredHandler(encryptResponse.value()).encrypt(body, selectedContentType, sessionContext);
        } catch (GeneralSecurityException e) {
            throw new ResponseEncryptionException("Failed to encrypt response body", e);
        }
    }

    private CryptoSessionContext getSessionContext() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            return null;
        }
        return (CryptoSessionContext) attrs.getAttribute(CryptoSessionContext.REQUEST_CONTEXT_KEY, RequestAttributes.SCOPE_REQUEST);
    }

    private EncryptResponse findEncryptResponse(MethodParameter returnType) {
        EncryptResponse annotation = returnType.getMethodAnnotation(EncryptResponse.class);
        if (annotation != null) {
            return annotation;
        }
        return AnnotatedElementUtils.findMergedAnnotation(returnType.getContainingClass(), EncryptResponse.class);
    }
}
