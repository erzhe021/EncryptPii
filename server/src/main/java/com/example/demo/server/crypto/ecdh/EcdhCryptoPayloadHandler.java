package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.DefaultAesCipherPayload;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.SessionKeyTransport;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhContext;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.CryptoPayloadHandler;
import com.example.demo.server.crypto.CryptoSessionContext;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

@Component
@Slf4j
public class EcdhCryptoPayloadHandler implements CryptoPayloadHandler {
    private final EcdhCryptoServer ecdhCryptoServer;
    private final ObjectMapper objectMapper;

    public EcdhCryptoPayloadHandler(EcdhCryptoServer ecdhCryptoServer, ObjectMapper objectMapper) {
        this.ecdhCryptoServer = ecdhCryptoServer;
        this.objectMapper = objectMapper;
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return CryptoAlgorithm.ECDH;
    }

    /**
     * Decrypts the given encrypted request body using ECDH.
     *
     * @param encryptedRequestBody The encrypted request body as a JSON string.
     * @return The decrypted request body as a string.
     * @throws GeneralSecurityException If there is an error during decryption.
     */
    @Override
    public String decrypt(String encryptedRequestBody) throws GeneralSecurityException {
        log.info("decrypt encryptedRequestBody={}", encryptedRequestBody);
        try {
            EcdhCipherPayload payload = objectMapper.readValue(encryptedRequestBody, EcdhCipherPayload.class);
            return ecdhCryptoServer.decrypt(payload);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid ECDH encrypted request payload", e);
        }
    }

    /**
     * Creates a CryptoSessionContext based on the given encrypted request body.
     *
     * @param encryptedRequestBody The encrypted request body as a JSON string.
     * @return A CryptoSessionContext containing information about the cryptographic session.
     */
    @Override
    public CryptoSessionContext createSessionContext(String encryptedRequestBody) {
        log.info("createSessionContext encryptedRequestBody={}", encryptedRequestBody);
        try {
            EcdhCipherPayload payload = objectMapper.readValue(encryptedRequestBody, EcdhCipherPayload.class);
            return new CryptoSessionContext(CryptoAlgorithm.ECDH, payload);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Invalid ECDH encrypted request payload", e);
        }
    }

    /**
     * Encrypts the response body using the session context.
     *
     * @param responseBody   The response body to encrypt.
     * @param sessionContext The session context containing the encryption parameters.
     * @return The encrypted response body.
     * @throws GeneralSecurityException If there is an error during encryption.
     */
    @Override
    public Object encrypt(Object responseBody, CryptoSessionContext sessionContext)
            throws GeneralSecurityException {

        log.info("encrypt responseBody={} with sessionContext={}", responseBody, sessionContext);

        try {
            String responseBodyString = objectMapper.writeValueAsString(responseBody);
            if (sessionContext.requestKeyMaterial() instanceof SessionKeyTransport sessionKeyTransport) {
                SecretKey sessionKey = new SecretKeySpec(
                        EncodingUtils.fromBase64(sessionKeyTransport.sessionKeyBase64()),
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
            if (sessionContext.requestKeyMaterial() instanceof EcdhContext ecdhContext) {
                return ecdhCryptoServer.encryptWithEcdhContext(
                        responseBodyString,
                        ecdhContext
                );
            }

            EcdhCipherPayload requestPayload = (EcdhCipherPayload) sessionContext.requestKeyMaterial();
            EcdhContext ecdhContext = new EcdhContext(
                    requestPayload.clientEphemeralPublicKeyBase64(),
                    requestPayload.serverEphemeralPublicKeyBase64()
            );
            return ecdhCryptoServer.encryptWithEcdhContext(
                    responseBodyString,
                    ecdhContext
            );
        } catch (JsonProcessingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalArgumentException("Failed to serialize response body before ECDH encryption", e);
        }
    }
}
