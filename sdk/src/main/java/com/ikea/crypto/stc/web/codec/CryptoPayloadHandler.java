package com.ikea.crypto.stc.web.codec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.stc.exception.InvalidCryptoPayloadException;
import com.ikea.crypto.stc.exception.ResponseEncryptionException;
import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.CipherResponsePayload;
import com.ikea.crypto.stc.model.SessionKeyTransport;
import com.ikea.crypto.stc.session.CryptoSessionContext;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import com.ikea.crypto.stc.util.EncodingUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

@Component
@Slf4j
public class CryptoPayloadHandler {

    private final CryptoServer cryptoServer;
    private final ObjectMapper objectMapper;

    public CryptoPayloadHandler(CryptoServer cryptoServer, ObjectMapper objectMapper) {
        this.cryptoServer = cryptoServer;
        this.objectMapper = objectMapper;
    }

    public CryptoSessionContext createSessionContext(String encryptedRequestBody) {
        return createSessionContext(encryptedRequestBody, null, null);
    }

    public CryptoSessionContext createSessionContext(String encryptedRequestBody, String keyId, String encryptedSessionKey) {
        if (keyId == null || keyId.isBlank() || encryptedSessionKey == null || encryptedSessionKey.isBlank()) {
            throw new InvalidCryptoPayloadException(
                    "X-STC-Key-Id and X-STC-Session-Key are required; body key transport is unsupported");
        }
        try {
            var body = objectMapper.readTree(encryptedRequestBody);
            if (body == null || !body.isObject()
                    || body.size() != 2
                    || !body.has("ivBase64")
                    || !body.has("encryptedDataBase64")
                    || !body.get("ivBase64").isTextual()
                    || !body.get("encryptedDataBase64").isTextual()) {
                throw new InvalidCryptoPayloadException(
                        "Request body may contain only ivBase64 and encryptedDataBase64");
            }
            CipherRequestPayload payload = new CipherRequestPayload(
                    keyId,
                    encryptedSessionKey,
                    body.get("ivBase64").asText(null),
                    body.get("encryptedDataBase64").asText(null));
            cryptoServer.validatePayload(payload);
            return CryptoSessionContext.request(payload);
        } catch (JsonProcessingException e) {
            throw new InvalidCryptoPayloadException("Invalid RSA encrypted request payload", e);
        }
    }

    public String decrypt(String encryptedRequestBody) throws GeneralSecurityException {
        CryptoSessionContext sessionContext = createSessionContext(encryptedRequestBody);
        return decrypt(sessionContext);
    }

    public String decrypt(CryptoSessionContext sessionContext) throws GeneralSecurityException {
        if (sessionContext == null || !(sessionContext.requestKeyMaterial() instanceof CipherRequestPayload payload)) {
            throw new InvalidCryptoPayloadException(
                    "Unsupported RSA session key material: " + (sessionContext == null ? null : sessionContext.requestKeyMaterial())
            );
        }
        return cryptoServer.decrypt(payload);
    }

    public Object encrypt(Object responseBody, CryptoSessionContext sessionContext) {
        if (sessionContext == null || sessionContext.requestKeyMaterial() == null) {
            throw new InvalidCryptoPayloadException("Session context is required for RSA operations");
        }

        String responseBodyString;
        try {
            responseBodyString = objectMapper.writeValueAsString(responseBody);
        } catch (JsonProcessingException e) {
            throw new ResponseEncryptionException("Failed to serialize response body before encryption", e);
        }

        try {
            if (sessionContext.requestKeyMaterial() instanceof SessionKeyTransport transport) {
                SecretKey sessionKey = CryptoSessionContextAccessor.getResolvedSessionKey();
                if (sessionKey == null) {
                    sessionKey = cryptoServer.decryptSessionKeyToSecretKey(
                            transport.keyId(), transport.encryptedSessionKeyBase64());
                }
                byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
                String encryptedDataBase64 = AesGcmCipher.encryptAsBase64(responseBodyString, sessionKey, iv);
                return new CipherResponsePayload(EncodingUtils.toBase64(iv), encryptedDataBase64);
            }
            if (sessionContext.requestKeyMaterial() instanceof CipherRequestPayload requestPayload) {
                cryptoServer.validatePayload(requestPayload);
                SecretKey sessionKey = CryptoSessionContextAccessor.getResolvedSessionKey();
                if (sessionKey == null) {
                    sessionKey = cryptoServer.decryptSessionKeyToSecretKey(
                            requestPayload.keyId(), requestPayload.encryptedSessionKeyBase64());
                }
                byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
                String encryptedDataBase64 = AesGcmCipher.encryptAsBase64(responseBodyString, sessionKey, iv);
                return new CipherResponsePayload(EncodingUtils.toBase64(iv), encryptedDataBase64);
            }
        } catch (GeneralSecurityException e) {
            throw new ResponseEncryptionException("Failed to encrypt response body", e);
        }

        throw new InvalidCryptoPayloadException("Unsupported RSA session key material: " + sessionContext.requestKeyMaterial());
    }
}
