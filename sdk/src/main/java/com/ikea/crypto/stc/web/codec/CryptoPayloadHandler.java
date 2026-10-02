package com.ikea.crypto.stc.web.codec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.constant.CryptoConstants;
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
import javax.crypto.spec.SecretKeySpec;
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
        try {
            CipherRequestPayload payload = objectMapper.readValue(encryptedRequestBody, CipherRequestPayload.class);
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
            if (sessionContext.requestKeyMaterial() instanceof SessionKeyTransport sessionKeyTransport) {
                SecretKey sessionKey = new SecretKeySpec(
                        cryptoServer.decryptSessionKey(sessionKeyTransport.keyId(), sessionKeyTransport.encryptedSessionKeyBase64()),
                        CryptoConstants.ALGORITHM_AES
                );
                byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
                String encryptedDataBase64 = AesGcmCipher.encryptAsBase64(responseBodyString, sessionKey, iv);
                return new CipherResponsePayload(EncodingUtils.toBase64(iv), encryptedDataBase64);
            }

            if (sessionContext.requestKeyMaterial() instanceof CipherRequestPayload requestPayload) {
                cryptoServer.validatePayload(requestPayload);
                SecretKey sessionKey = CryptoSessionContextAccessor.getResolvedSessionKey();
                if (sessionKey == null) {
                    sessionKey = cryptoServer.decryptSessionKeyToSecretKey(requestPayload.keyId(), requestPayload.encryptedSessionKeyBase64());
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
