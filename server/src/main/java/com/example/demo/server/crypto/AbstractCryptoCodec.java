package com.example.demo.server.crypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.GeneralSecurityException;

public abstract class AbstractCryptoCodec implements CryptoCodec {
    protected final ObjectMapper objectMapper;

    protected AbstractCryptoCodec(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public final String decrypt(String encryptedRequestBody, CryptoSessionContext<?> sessionContext) throws GeneralSecurityException {
        validateSessionContext(sessionContext);
        return doDecrypt(sessionContext);
    }

    @Override
    public final Object encrypt(Object responseBody, CryptoSessionContext<?> sessionContext) throws GeneralSecurityException {
        validateSessionContext(sessionContext);
        String responseBodyString = serializeResponseBody(responseBody);
        return doEncrypt(responseBodyString, sessionContext);
    }

    protected abstract String doDecrypt(CryptoSessionContext<?> sessionContext) throws GeneralSecurityException;

    protected abstract Object doEncrypt(String responseBodyString, CryptoSessionContext<?> sessionContext)
            throws GeneralSecurityException;

    protected final String serializeResponseBody(Object responseBody) {
        try {
            return objectMapper.writeValueAsString(responseBody);
        } catch (JsonProcessingException e) {
            throw new ResponseEncryptionException(
                    "Failed to serialize response body before " + algorithm().name() + " encryption",
                    e
            );
        }
    }

    protected final void validateSessionContext(CryptoSessionContext<?> sessionContext) {
        if (sessionContext == null || sessionContext.requestKeyMaterial() == null) {
            throw new InvalidCryptoPayloadException("Session context is required for " + algorithm().name() + " operations");
        }
    }
}
