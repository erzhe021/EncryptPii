package com.ikea.crypto.stc.web.codec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.GcmIvGenerator;
import com.ikea.crypto.stc.exception.InvalidCryptoPayloadException;
import com.ikea.crypto.stc.exception.ResponseEncryptionException;
import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.CipherResponsePayload;
import com.ikea.crypto.stc.model.SessionKeyHeaders;
import com.ikea.crypto.stc.session.CryptoSessionContext;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import com.ikea.crypto.stc.util.EncodingUtils;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

public class CryptoPayloadHandler {

    private final CryptoServer cryptoServer;
    private final ObjectMapper objectMapper;

    private static final String IV_FIELD = "ivBase64";
    private static final String ENCRYPTED_DATA_FIELD = "encryptedDataBase64";

    public CryptoPayloadHandler(CryptoServer cryptoServer, ObjectMapper objectMapper) {
        this.cryptoServer = cryptoServer;
        this.objectMapper = objectMapper;
    }

    public CryptoSessionContext createSessionContext(String encryptedRequestBody, SessionKeyHeaders sessionKeyHeaders) {
        if (sessionKeyHeaders == null) {
            throw new InvalidCryptoPayloadException("Session key transport headers are required.");
        }
        try {
            var body = objectMapper.readTree(encryptedRequestBody);
            if (body == null || !body.isObject()
                    || body.size() != 2
                    || !body.has(IV_FIELD)
                    || !body.has(ENCRYPTED_DATA_FIELD)
                    || !body.get(IV_FIELD).isTextual()
                    || !body.get(ENCRYPTED_DATA_FIELD).isTextual()) {
                throw new InvalidCryptoPayloadException(
                        "Request body may contain only ivBase64 and encryptedDataBase64");
            }
            CipherRequestPayload payload = new CipherRequestPayload(
                    body.get(IV_FIELD).asText(null),
                    body.get(ENCRYPTED_DATA_FIELD).asText(null));
            cryptoServer.validatePayload(payload);
            return CryptoSessionContext.request(payload, sessionKeyHeaders);
        } catch (JsonProcessingException e) {
            throw new InvalidCryptoPayloadException("Invalid RSA encrypted request payload", e);
        }
    }

    public String decrypt(CryptoSessionContext sessionContext) throws GeneralSecurityException {
        if (sessionContext == null) {
            throw new InvalidCryptoPayloadException("Crypto session context is required for request decryption");
        }
        CipherRequestPayload payload = sessionContext.requireRequestPayload();
        SessionKeyHeaders headers = sessionContext.sessionKeyHeaders();
        SecretKey sessionKey = cryptoServer.decryptSessionKeyToSecretKey(
                headers.keyId(), headers.encryptedSessionKeyBase64());
        String decryptedBody = cryptoServer.decrypt(payload, sessionKey);
        CryptoSessionContextAccessor.setResolvedSessionKey(sessionKey);
        return decryptedBody;
    }

    public CryptoSessionContext createResponseSessionContext(SessionKeyHeaders headers) {
        CryptoSessionContext context = CryptoSessionContext.responseOnly(headers);
        try {
            SecretKey sessionKey = cryptoServer.decryptSessionKeyToSecretKey(
                    headers.keyId(), headers.encryptedSessionKeyBase64());
            CryptoSessionContextAccessor.setResolvedSessionKey(sessionKey);
            return context;
        } catch (GeneralSecurityException e) {
            throw new InvalidCryptoPayloadException("Failed to decrypt session key", e);
        }
    }

    public Object encrypt(Object responseBody, CryptoSessionContext sessionContext) {
        String responseBodyString;
        try {
            responseBodyString = objectMapper.writeValueAsString(responseBody);
        } catch (JsonProcessingException e) {
            throw new ResponseEncryptionException("Failed to serialize response body before encryption", e);
        }

        try {
            SecretKey sessionKey = CryptoSessionContextAccessor.getResolvedSessionKey();
            if (sessionKey == null) {
                SessionKeyHeaders headers = sessionContext.sessionKeyHeaders();
                sessionKey = cryptoServer.decryptSessionKeyToSecretKey(
                        headers.keyId(), headers.encryptedSessionKeyBase64());
            }
            byte[] iv = GcmIvGenerator.generateIv();
            String encryptedDataBase64 = AesGcmCipher.encryptAsBase64(responseBodyString, sessionKey, iv);
            return new CipherResponsePayload(EncodingUtils.toBase64(iv), encryptedDataBase64);
        } catch (GeneralSecurityException e) {
            throw new ResponseEncryptionException("Failed to encrypt response body", e);
        }
    }
}
