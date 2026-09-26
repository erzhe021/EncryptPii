package com.ikea.crypto.server.advice;

import com.ikea.crypto.server.codec.CryptoPayloadHandlerRegistry;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.error.CryptoException;
import com.ikea.crypto.server.error.ResponseEncryptionException;
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
public class ResponseEncryptAdvice implements ResponseBodyAdvice<Object> {

    private final CryptoPayloadHandlerRegistry handlerRegistry;

    public ResponseEncryptAdvice(CryptoPayloadHandlerRegistry handlerRegistry) {
        this.handlerRegistry = handlerRegistry;
    }

    /**
     * Check if the method return type is annotated with @EncryptResponse.
     * If so, this advice will be applied to encrypt the response body.
     */
    @Override
    public boolean supports(MethodParameter returnType,
                            Class<? extends HttpMessageConverter<?>> converterType) {
        return findEncryptResponse(returnType) != null;
    }

    /**
     * Encrypt the response body before it is written to the HTTP response.
     * The response body is encrypted using the appropriate handler and session context.
     */
    @Override
    public Object beforeBodyWrite(Object body,
                                  MethodParameter returnType,
                                  MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  ServerHttpRequest request,
                                  ServerHttpResponse response) {
        EncryptResponse encryptResponse = findEncryptResponse(returnType);
        if (encryptResponse == null || body == null) {
            return body;
        }
        try {
            // Get the CryptoSessionContext for response encryption
            CryptoSessionContext<?> sessionContext = CryptoSessionContextAccessor.getCryptoSessionContext();
            if (sessionContext == null) {
                throw new CryptoException("No request session context available for response encryption");
            }
            // Encrypt the response body using the appropriate handler
            return handlerRegistry.getRequiredHandler(encryptResponse.value()).encrypt(body, sessionContext);
        } catch (GeneralSecurityException e) {
            throw new ResponseEncryptionException("Failed to encrypt response body", e);
        }
    }

    /**
     * Find the @EncryptResponse annotation on the method return type.
     */
    private EncryptResponse findEncryptResponse(MethodParameter returnType) {
        return CryptoAdviceSupport.findAnnotation(returnType, EncryptResponse.class);
    }
}
