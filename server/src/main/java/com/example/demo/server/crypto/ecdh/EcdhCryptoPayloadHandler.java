package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.ClientSessionKeyTransport;
import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.CryptoPayloadHandler;
import com.example.demo.server.crypto.CryptoSessionContext;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

@Component
public class EcdhCryptoPayloadHandler implements CryptoPayloadHandler {
    private final EcdhCryptoServer cryptoServer;
    private final ObjectMapper objectMapper;

    public EcdhCryptoPayloadHandler(EcdhCryptoServer cryptoServer, ObjectMapper objectMapper) {
        this.cryptoServer = cryptoServer;
        this.objectMapper = objectMapper;
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return CryptoAlgorithm.ECDH;
    }

    @Override
    public String decrypt(String requestBody, Type targetType) throws GeneralSecurityException {
        try {
            EcdhCipherPayload payload = objectMapper.readValue(requestBody, EcdhCipherPayload.class);
            return cryptoServer.decrypt(payload);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid ECDH encrypted request payload", e);
        }
    }

    @Override
    public CryptoSessionContext createSessionContext(String requestBody) throws GeneralSecurityException {
        try {
            EcdhCipherPayload payload = objectMapper.readValue(requestBody, EcdhCipherPayload.class);
            return new CryptoSessionContext(CryptoAlgorithm.ECDH, requestBody, payload);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid ECDH encrypted request payload", e);
        }
    }

    @Override
    public Object encrypt(Object responseBody, MediaType mediaType, CryptoSessionContext sessionContext) throws GeneralSecurityException {
        try {
            String plainJson = objectMapper.writeValueAsString(responseBody);
            if (sessionContext.requestKeyMaterial() instanceof ClientSessionKeyTransport sessionKeyTransport) {
                SecretKey sessionKey = new SecretKeySpec(
                        EncodingUtils.fromBase64(sessionKeyTransport.sessionKeyBase64()),
                        CryptoConstants.ALGORITHM_AES
                );
                byte[] iv = EncodingUtils.fromBase64(sessionKeyTransport.ivBase64());
                Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
                aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
                byte[] encryptedData = aesCipher.doFinal(plainJson.getBytes(StandardCharsets.UTF_8));
                return new EcdhCipherPayload(
                        "",
                        "",
                        sessionKeyTransport.ivBase64(),
                        EncodingUtils.toBase64(encryptedData)
                );
            }

            EcdhCipherPayload requestPayload = (EcdhCipherPayload) sessionContext.requestKeyMaterial();
            return cryptoServer.encryptWithRequestPayload(plainJson, requestPayload);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Failed to serialize response body before ECDH encryption", e);
        }
    }
}
