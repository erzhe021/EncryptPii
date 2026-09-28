package com.ikea.crypto.server.advice;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.error.CryptoException;
import com.ikea.crypto.server.error.ResponseEncryptionException;
import com.ikea.crypto.server.service.CryptoServer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

import java.security.GeneralSecurityException;

@ControllerAdvice
@Slf4j
public class ResponseEncryptAdvice implements ResponseBodyAdvice<Object> {

    private final CryptoServer cryptoServer;
    private final ObjectMapper objectMapper;

    public ResponseEncryptAdvice(CryptoServer cryptoServer, ObjectMapper objectMapper) {
        this.cryptoServer = cryptoServer;
        this.objectMapper = objectMapper;
    }

    @Override
    public boolean supports(MethodParameter returnType,
                            Class<? extends HttpMessageConverter<?>> converterType) {
        return findEncryptResponse(returnType) != null;
    }

    @Override
    public Object beforeBodyWrite(Object body,
                                  MethodParameter returnType,
                                  MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  ServerHttpRequest request,
                                  ServerHttpResponse response) {
        log.debug("【api post-called】start to encrypting response body");
        EncryptResponse encryptResponse = findEncryptResponse(returnType);
        if (encryptResponse == null || body == null) {
            return body;
        }
        try {
            CryptoSessionContext sessionContext = CryptoSessionContextAccessor.getCryptoSessionContext();
            if (sessionContext == null || sessionContext.handshakeContext() == null) {
                throw new CryptoException("No request session context available for response encryption");
            }
            String responseBodyString = objectMapper.writeValueAsString(body);
            return cryptoServer.encryptWithEcdhHandshakeContext(responseBodyString, sessionContext.handshakeContext());
        } catch (GeneralSecurityException | JsonProcessingException e) {
            throw new ResponseEncryptionException("Failed to encrypt response body", e);
        } finally {
            CryptoSessionContextAccessor.clearCryptoSessionContext();
        }
    }

    private EncryptResponse findEncryptResponse(MethodParameter returnType) {
        return CryptoAdviceSupport.findAnnotation(returnType, EncryptResponse.class);
    }
}
