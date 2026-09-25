package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.CryptoEnvelopeParser;
import com.example.demo.server.crypto.CryptoSessionContext;
import com.example.demo.server.crypto.InvalidCryptoPayloadException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class EcdhCryptoEnvelopeParser implements CryptoEnvelopeParser {
    private final ObjectMapper objectMapper;

    public EcdhCryptoEnvelopeParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return CryptoAlgorithm.ECDH;
    }

    @Override
    public CryptoSessionContext<?> parse(String encryptedRequestBody) {
        try {
            EcdhCipherPayload payload = objectMapper.readValue(encryptedRequestBody, EcdhCipherPayload.class);
            return CryptoSessionContext.ecdh(payload);
        } catch (JsonProcessingException e) {
            throw new InvalidCryptoPayloadException("Invalid ECDH encrypted request payload", e);
        }
    }
}
