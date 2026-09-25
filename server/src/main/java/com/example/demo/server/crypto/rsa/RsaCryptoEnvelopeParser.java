package com.example.demo.server.crypto.rsa;

import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.CryptoEnvelopeParser;
import com.example.demo.server.crypto.CryptoSessionContext;
import com.example.demo.server.crypto.InvalidCryptoPayloadException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class RsaCryptoEnvelopeParser implements CryptoEnvelopeParser {
    private final ObjectMapper objectMapper;

    public RsaCryptoEnvelopeParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return CryptoAlgorithm.RSA;
    }

    @Override
    public CryptoSessionContext<?> parse(String encryptedRequestBody) {
        try {
            RsaCipherPayload payload = objectMapper.readValue(encryptedRequestBody, RsaCipherPayload.class);
            return CryptoSessionContext.rsa(payload);
        } catch (JsonProcessingException e) {
            throw new InvalidCryptoPayloadException("Invalid RSA encrypted request payload", e);
        }
    }
}
