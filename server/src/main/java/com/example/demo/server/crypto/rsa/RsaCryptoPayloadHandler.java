package com.example.demo.server.crypto.rsa;

import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.CryptoPayloadHandler;
import com.example.demo.server.crypto.CryptoSessionContext;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.lang.reflect.Type;
import java.security.GeneralSecurityException;

@Component
public class RsaCryptoPayloadHandler implements CryptoPayloadHandler {
    private final RsaCryptoServer cryptoServer;
    private final ObjectMapper objectMapper;

    public RsaCryptoPayloadHandler(RsaCryptoServer cryptoServer, ObjectMapper objectMapper) {
        this.cryptoServer = cryptoServer;
        this.objectMapper = objectMapper;
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return CryptoAlgorithm.RSA;
    }

    @Override
    public String decrypt(String requestBody, Type targetType) throws GeneralSecurityException {
        try {
            RsaCipherPayload payload = objectMapper.readValue(requestBody, RsaCipherPayload.class);
            return cryptoServer.decrypt(payload);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid RSA encrypted request payload", e);
        }
    }

    @Override
    public CryptoSessionContext createSessionContext(String requestBody) throws GeneralSecurityException {
        try {
            RsaCipherPayload payload = objectMapper.readValue(requestBody, RsaCipherPayload.class);
            return new CryptoSessionContext(CryptoAlgorithm.RSA, requestBody, payload);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid RSA encrypted request payload", e);
        }
    }

    @Override
    public Object encrypt(Object responseBody, MediaType mediaType, CryptoSessionContext sessionContext) throws GeneralSecurityException {
        try {
            String plainJson = objectMapper.writeValueAsString(responseBody);
            RsaCipherPayload requestPayload = (RsaCipherPayload) sessionContext.getRequestKeyMaterial();
            return cryptoServer.encryptWithRequestPayload(plainJson, requestPayload);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Failed to serialize response body before RSA encryption", e);
        }
    }
}
