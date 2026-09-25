package com.example.demo.server.crypto;

import lombok.extern.slf4j.Slf4j;
import org.checkerframework.checker.nullness.qual.NonNull;
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

    private final CryptoPayloadHandlerRegistry handlerRegistry;

    public RequestDecryptAdvice(CryptoPayloadHandlerRegistry handlerRegistry) {
        this.handlerRegistry = handlerRegistry;
    }

    @Override
    public boolean supports(@NonNull MethodParameter methodParameter,
                            @NonNull Type targetType,
                            @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        return findDecryptRequest(methodParameter) != null;
    }

    /**
     * Decrypt the request body before it is read and converted to an object.
     * The decrypted JSON string is then wrapped in a new HttpInputMessage and returned.
     */
    @Override
    public @NonNull HttpInputMessage beforeBodyRead(@NonNull HttpInputMessage inputMessage,
                                                    @NonNull MethodParameter parameter,
                                                    @NonNull Type targetType,
                                                    @NonNull Class<? extends HttpMessageConverter<?>> converterType)
            throws IOException {
        log.info("Decrypting request body for method: {} in class: {}", parameter.getMethod(), parameter.getContainingClass());
        DecryptRequest decryptRequest = findDecryptRequest(parameter);
        if (decryptRequest == null) {
            return inputMessage;
        }
        String encryptedBody = new String(inputMessage.getBody().readAllBytes(), StandardCharsets.UTF_8);
        String decryptedBody;
        try {
            CryptoPayloadHandler handler = handlerRegistry.getRequiredHandler(decryptRequest.value());
            CryptoSessionContext<?> sessionContext = handler.createSessionContext(encryptedBody);
            CryptoSessionContextAccessor.setCryptoSessionContext(sessionContext);
            decryptedBody = handler.decrypt(encryptedBody);
        } catch (GeneralSecurityException e) {
            throw new InvalidCryptoPayloadException("Failed to decrypt request body", e);
        }

        return new HttpInputMessage() {
            @Override
            public @NonNull InputStream getBody() {
                return new ByteArrayInputStream(decryptedBody.getBytes(StandardCharsets.UTF_8));
            }

            @Override
            public @NonNull HttpHeaders getHeaders() {
                return inputMessage.getHeaders();
            }
        };
    }

    /**
     * After the body is read and converted to an object, we can perform additional processing if needed.
     * In this case, we simply return the body as is.
     */
    @Override
    public @NonNull Object afterBodyRead(@NonNull Object body,
                                         @NonNull HttpInputMessage inputMessage,
                                         @NonNull MethodParameter parameter,
                                         @NonNull Type targetType,
                                         @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }

    /**
     * If the request body is empty, we can handle it here. In this case, we simply return the body as is.
     */
    @Override
    public @NonNull Object handleEmptyBody(Object body,
                                           @NonNull HttpInputMessage inputMessage,
                                           @NonNull MethodParameter parameter,
                                           @NonNull Type targetType,
                                           @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        return body;
    }

    /**
     * Find the DecryptRequest annotation on the method or class.
     *
     * @param methodParameter the method parameter
     * @return the DecryptRequest annotation, or null if not found
     */
    private DecryptRequest findDecryptRequest(MethodParameter methodParameter) {
        return CryptoAdviceSupport.findAnnotation(methodParameter, DecryptRequest.class);
    }
}
