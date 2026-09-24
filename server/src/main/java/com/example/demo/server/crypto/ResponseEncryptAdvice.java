package com.example.demo.server.crypto;

import lombok.extern.slf4j.Slf4j;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.security.GeneralSecurityException;

/**
 * Advice to encrypt the response body for methods annotated with @EncryptResponse.
 * The response body is encrypted using the same algorithm and session context as the request.
 */
@ControllerAdvice
@Slf4j
public class ResponseEncryptAdvice implements ResponseBodyAdvice<Object> {

    private final CryptoPayloadHandlerRegistry handlerRegistry;

    public ResponseEncryptAdvice(CryptoPayloadHandlerRegistry handlerRegistry) {
        this.handlerRegistry = handlerRegistry;
    }

    @Override
    public boolean supports(@NonNull MethodParameter returnType,
                            @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        return findEncryptResponse(returnType) != null;
    }

    @Override
    public Object beforeBodyWrite(Object body,
                                  @NonNull MethodParameter returnType,
                                  @NonNull MediaType selectedContentType,
                                  @NonNull Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  @NonNull ServerHttpRequest request,
                                  @NonNull ServerHttpResponse response) {
        log.info("Encrypting response body for method: {} in class: {}", returnType.getMethod(), returnType.getContainingClass());
        EncryptResponse encryptResponse = findEncryptResponse(returnType);
        if (encryptResponse == null || body == null) {
            return body;
        }
        try {
            CryptoSessionContext sessionContext = getSessionContext();
            if (sessionContext == null) {
                throw new IllegalStateException("No request session context available for response encryption");
            }
            return handlerRegistry.getRequiredHandler(encryptResponse.value()).encrypt(body, sessionContext);
        } catch (GeneralSecurityException e) {
            throw new ResponseEncryptionException("Failed to encrypt response body", e);
        }
    }

    private CryptoSessionContext getSessionContext() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            return null;
        }
        return (CryptoSessionContext) attrs.getAttribute(
                CryptoSessionContext.REQUEST_CONTEXT_KEY, RequestAttributes.SCOPE_REQUEST);
    }

    private EncryptResponse findEncryptResponse(MethodParameter returnType) {
        EncryptResponse annotation = returnType.getMethodAnnotation(EncryptResponse.class);
        if (annotation != null) {
            return annotation;
        }
        return AnnotatedElementUtils.findMergedAnnotation(returnType.getContainingClass(), EncryptResponse.class);
    }
}
