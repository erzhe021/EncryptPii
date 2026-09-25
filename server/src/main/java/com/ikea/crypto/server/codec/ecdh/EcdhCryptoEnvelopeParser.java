package com.ikea.crypto.server.codec.ecdh;

import com.ikea.crypto.common.ecdh.EcdhCipherPayload;
import com.ikea.crypto.server.model.CryptoAlgorithm;
import com.ikea.crypto.server.codec.CryptoEnvelopeParser;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.error.InvalidCryptoPayloadException;
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
