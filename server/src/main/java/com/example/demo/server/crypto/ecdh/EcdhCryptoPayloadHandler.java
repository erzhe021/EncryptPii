package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.ecdh.EcdhCipherPayload;
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
public class EcdhCryptoPayloadHandler implements CryptoPayloadHandler {
    private final EcdhCryptoServer cryptoServer;
    private final ObjectMapper objectMapper;

    public EcdhCryptoPayloadHandler(EcdhCryptoServer cryptoServer, ObjectMapper objectMapper) {
        this.cryptoServer = cryptoServer;
        this.objectMapper = objectMapper;
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return CryptoAlgorithm.ECDH;
    }

    @Override
    public String decrypt(String requestBody, Type targetType) throws GeneralSecurityException {
        try {
            EcdhCipherPayload payload = objectMapper.readValue(requestBody, EcdhCipherPayload.class);
            return cryptoServer.decrypt(payload);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid ECDH encrypted request payload", e);
        }
    }

    @Override
    public CryptoSessionContext createSessionContext(String requestBody) throws GeneralSecurityException {
        try {
            EcdhCipherPayload payload = objectMapper.readValue(requestBody, EcdhCipherPayload.class);
            return new CryptoSessionContext(CryptoAlgorithm.ECDH, requestBody, payload);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid ECDH encrypted request payload", e);
        }
    }

    @Override
    public Object encrypt(Object responseBody, MediaType mediaType, CryptoSessionContext sessionContext) throws GeneralSecurityException {
        try {
            String plainJson = objectMapper.writeValueAsString(responseBody);
            EcdhCipherPayload requestPayload = (EcdhCipherPayload) sessionContext.getRequestKeyMaterial();
            return cryptoServer.encryptWithRequestPayload(plainJson, requestPayload);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Failed to serialize response body before ECDH encryption", e);
        }
    }
}
