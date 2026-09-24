package com.example.demo.server.crypto.rsa;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.DefaultAesCipherPayload;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.SessionKeyTransport;
import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.CryptoPayloadHandler;
import com.example.demo.server.crypto.CryptoSessionContext;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * RsaCryptoPayloadHandler is responsible for handling RSA encrypted payloads.
 * It provides methods to decrypt incoming requests and encrypt outgoing responses using RSA and AES algorithms.
 */
@Component
@Slf4j
public class RsaCryptoPayloadHandler implements CryptoPayloadHandler {
    private final RsaCryptoServer rsaCryptoServer;
    private final ObjectMapper objectMapper;

    public RsaCryptoPayloadHandler(RsaCryptoServer rsaCryptoServer, ObjectMapper objectMapper) {
        this.rsaCryptoServer = rsaCryptoServer;
        this.objectMapper = objectMapper;
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return CryptoAlgorithm.RSA;
    }

    @Override
    public String decrypt(String encryptedRequestBody) throws GeneralSecurityException {
        log.info("decrypt encryptedRequestBody={}", encryptedRequestBody);
        try {
            RsaCipherPayload payload = objectMapper.readValue(encryptedRequestBody, RsaCipherPayload.class);
            return rsaCryptoServer.decrypt(payload);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid RSA encrypted request payload", e);
        }
    }

    @Override
    public CryptoSessionContext createSessionContext(String encryptedRequestBody) {
        log.info("createSessionContext encryptedRequestBody={}", encryptedRequestBody);
        try {
            RsaCipherPayload payload = objectMapper.readValue(encryptedRequestBody, RsaCipherPayload.class);
            return new CryptoSessionContext(CryptoAlgorithm.RSA, payload);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid RSA encrypted request payload", e);
        }
    }

    @Override
    public Object encrypt(Object responseBody, CryptoSessionContext sessionContext) {
        log.info("encrypt responseBody={} with sessionContext={}", responseBody, sessionContext);
        try {
            String responseBodyString = objectMapper.writeValueAsString(responseBody);
            if (sessionContext.requestKeyMaterial() instanceof SessionKeyTransport sessionKeyTransport) {
                SecretKey sessionKey = new SecretKeySpec(
                        rsaCryptoServer.decryptSessionKey(sessionKeyTransport.sessionKeyBase64()),
                        CryptoConstants.ALGORITHM_AES
                );
                byte[] iv = EncodingUtils.fromBase64(sessionKeyTransport.ivBase64());
                Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
                aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
                byte[] encryptedData = aesCipher.doFinal(responseBodyString.getBytes(StandardCharsets.UTF_8));
                return new DefaultAesCipherPayload(
                        sessionKeyTransport.ivBase64(),
                        EncodingUtils.toBase64(encryptedData)
                );
            }

            RsaCipherPayload requestPayload = (RsaCipherPayload) sessionContext.requestKeyMaterial();
            rsaCryptoServer.validatePayload(requestPayload);
            return rsaCryptoServer.encryptWithRequestSessionKey(responseBodyString, requestPayload.encryptedSessionKeyBase64());
        } catch (JsonProcessingException | GeneralSecurityException e) {
            throw new IllegalArgumentException("Failed to serialize response body before RSA encryption", e);
        }
    }
}
