package com.ikea.crypto.server.codec.rsa;

import com.ikea.crypto.common.rsa.RsaCipherPayload;
import com.ikea.crypto.server.model.CryptoAlgorithm;
import com.ikea.crypto.server.codec.CryptoEnvelopeParser;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.error.InvalidCryptoPayloadException;
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
