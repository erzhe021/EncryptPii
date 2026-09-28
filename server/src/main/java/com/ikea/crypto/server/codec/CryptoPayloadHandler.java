package com.ikea.crypto.server.codec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.crypto.AesGcmCryptoService;
import com.ikea.crypto.common.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.model.payload.CipherRequestPayload;
import com.ikea.crypto.common.model.payload.CipherResponsePayload;
import com.ikea.crypto.common.model.payload.SessionKeyTransport;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.error.InvalidCryptoPayloadException;
import com.ikea.crypto.server.error.ResponseEncryptionException;
import com.ikea.crypto.server.service.CryptoServer;
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

    public Object encrypt(Object responseBody, CryptoSessionContext sessionContext) throws GeneralSecurityException {
        if (sessionContext == null || sessionContext.requestKeyMaterial() == null) {
            throw new InvalidCryptoPayloadException("Session context is required for RSA operations");
        }

        String responseBodyString;
        try {
            responseBodyString = objectMapper.writeValueAsString(responseBody);
        } catch (JsonProcessingException e) {
            throw new ResponseEncryptionException("Failed to serialize response body before RSA encryption", e);
        }

        if (sessionContext.requestKeyMaterial() instanceof SessionKeyTransport sessionKeyTransport) {
            SecretKey sessionKey = new SecretKeySpec(
                    cryptoServer.decryptSessionKey(sessionKeyTransport.keyId(), sessionKeyTransport.encryptedSessionKeyBase64()),
                    CryptoConstants.ALGORITHM_AES
            );
            byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
            String encryptedDataBase64 = AesGcmCryptoService.encryptAsBase64(responseBodyString, sessionKey, iv);
            return new CipherResponsePayload(EncodingUtils.toBase64(iv), encryptedDataBase64);
        }

        if (sessionContext.requestKeyMaterial() instanceof CipherRequestPayload requestPayload) {
            cryptoServer.validatePayload(requestPayload);
            SecretKey sessionKey = CryptoSessionContextAccessor.getResolvedSessionKey();
            if (sessionKey == null) {
                sessionKey = cryptoServer.decryptSessionKeyToSecretKey(requestPayload.keyId(), requestPayload.encryptedSessionKeyBase64());
            }
            byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
            String encryptedDataBase64 = AesGcmCryptoService.encryptAsBase64(responseBodyString, sessionKey, iv);
            return new CipherResponsePayload(EncodingUtils.toBase64(iv), encryptedDataBase64);
        }

        throw new InvalidCryptoPayloadException("Unsupported RSA session key material: " + sessionContext.requestKeyMaterial());
    }
}
