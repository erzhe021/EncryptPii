package com.ikea.crypto.server.advice;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.common.model.CipherRequestPayload;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.error.InvalidCryptoPayloadException;
import com.ikea.crypto.server.service.CryptoServer;
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

    private final CryptoServer cryptoServer;
    private final ObjectMapper objectMapper;

    public RequestDecryptAdvice(CryptoServer cryptoServer, ObjectMapper objectMapper) {
        this.cryptoServer = cryptoServer;
        this.objectMapper = objectMapper;
    }

    @Override
    public boolean supports(MethodParameter methodParameter,
                            Type targetType,
                            Class<? extends HttpMessageConverter<?>> converterType) {
        return findDecryptRequest(methodParameter) != null;
    }

    @Override
    public HttpInputMessage beforeBodyRead(HttpInputMessage inputMessage,
                                         MethodParameter parameter,
                                         Type targetType,
                                         Class<? extends HttpMessageConverter<?>> converterType)
            throws IOException {
        log.debug("【api pre-called】start to decrypting request body");
        DecryptRequest decryptRequest = findDecryptRequest(parameter);
        if (decryptRequest == null) {
            return inputMessage;
        }
        String encryptedBody = new String(inputMessage.getBody().readAllBytes(), StandardCharsets.UTF_8);
        String decryptedBody;
        try {
            CipherRequestPayload payload = objectMapper.readValue(encryptedBody, CipherRequestPayload.class);
            CryptoSessionContextAccessor.setCryptoSessionContext(new CryptoSessionContext(payload.handshakeContext()));
            decryptedBody = cryptoServer.decrypt(payload);
        } catch (GeneralSecurityException | JsonProcessingException e) {
            throw new InvalidCryptoPayloadException("Failed to decrypt request body", e);
        }

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
        return body;
    }

    private DecryptRequest findDecryptRequest(MethodParameter methodParameter) {
        return CryptoAdviceSupport.findAnnotation(methodParameter, DecryptRequest.class);
    }
}
