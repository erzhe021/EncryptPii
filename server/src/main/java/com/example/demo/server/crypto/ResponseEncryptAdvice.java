package com.example.demo.server.crypto;

import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
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
        EncryptResponse encryptResponse = findEncryptResponse(returnType);
        if (encryptResponse == null || body == null) {
            return body;
        }
        try {
            CryptoSessionContext<?> sessionContext = CryptoSessionContextAccessor.getCryptoSessionContext();
            if (sessionContext == null) {
                throw new CryptoException("No request session context available for response encryption");
            }
            return handlerRegistry.getRequiredHandler(encryptResponse.value()).encrypt(body, sessionContext);
        } catch (GeneralSecurityException e) {
            throw new ResponseEncryptionException("Failed to encrypt response body", e);
        }
    }

    private EncryptResponse findEncryptResponse(MethodParameter returnType) {
        return CryptoAdviceSupport.findAnnotation(returnType, EncryptResponse.class);
    }
}
