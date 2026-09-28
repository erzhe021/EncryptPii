package com.ikea.crypto.server;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.crypto.AesGcmCryptoService;
import com.ikea.crypto.common.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.crypto.SessionKeyService;
import com.ikea.crypto.common.model.payload.CipherResponsePayload;
import com.ikea.crypto.common.model.payload.CipherRequestPayload;
import com.ikea.crypto.common.model.payload.SessionKeyTransport;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.server.codec.CryptoPayloadHandler;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.error.InvalidCryptoPayloadException;
import com.ikea.crypto.server.service.CryptoServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CryptoPayloadHandlerTest {

    private CryptoPayloadHandler payloadHandler;
    private CryptoServer cryptoServer;
    private ObjectMapper objectMapper;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();

        cryptoServer = new CryptoServer(keyPair.getPrivate(), keyPair.getPublic());
        objectMapper = new ObjectMapper();
        payloadHandler = new CryptoPayloadHandler(cryptoServer, objectMapper);
    }

    @AfterEach
    void tearDown() {
        CryptoSessionContextAccessor.clearCryptoSessionContext();
    }

    @Test
    void testDecryptFromString() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey sessionKey = keyGenerator.generateKey();

        byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        String plaintext = "{\"message\":\"hello payload handler\"}";

        String encryptedData = AesGcmCryptoService.encryptAsBase64(plaintext, sessionKey, iv);
        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, keyPair.getPublic());

        CipherRequestPayload payload = new CipherRequestPayload(
                encryptedSessionKey,
                EncodingUtils.toBase64(iv),
                encryptedData
        );
        String jsonPayload = objectMapper.writeValueAsString(payload);

        String decrypted = payloadHandler.decrypt(jsonPayload);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void testEncryptWithSessionKeyTransport() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey sessionKey = keyGenerator.generateKey();

        SessionKeyTransport transport = SessionKeyTransport.fromGeneratedKey(sessionKey, keyPair.getPublic());
        CryptoSessionContext context = CryptoSessionContext.responseOnly(transport);

        Map<String, String> responseBody = Map.of("status", "success");
        Object result = payloadHandler.encrypt(responseBody, context);

        assertInstanceOf(CipherResponsePayload.class, result);
        CipherResponsePayload aesPayload = (CipherResponsePayload) result;
        assertNotNull(aesPayload.ivBase64());
        assertNotNull(aesPayload.encryptedDataBase64());

        // Decrypt and verify
        String decrypted = AesGcmCryptoService.decryptFromBase64(
                aesPayload.encryptedDataBase64(),
                sessionKey,
                aesPayload.ivBase64()
        );
        assertEquals(objectMapper.writeValueAsString(responseBody), decrypted);
    }

    @Test
    void testEncryptWithCipherPayload() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey sessionKey = keyGenerator.generateKey();

        byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, keyPair.getPublic());

        CipherRequestPayload requestPayload = new CipherRequestPayload(
                encryptedSessionKey,
                EncodingUtils.toBase64(iv),
                "dummyData"
        );
        CryptoSessionContext context = CryptoSessionContext.request(requestPayload);

        Map<String, String> responseBody = Map.of("reply", "world");
        Object result = payloadHandler.encrypt(responseBody, context);

        assertInstanceOf(CipherResponsePayload.class, result);
        CipherResponsePayload aesPayload = (CipherResponsePayload) result;

        String decrypted = AesGcmCryptoService.decryptFromBase64(
                aesPayload.encryptedDataBase64(),
                sessionKey,
                aesPayload.ivBase64()
        );
        assertEquals(objectMapper.writeValueAsString(responseBody), decrypted);
    }

    @Test
    void testCreateSessionContextThrowsOnInvalidJson() {
        assertThrows(InvalidCryptoPayloadException.class, () ->
                payloadHandler.createSessionContext("not valid json")
        );
    }
}
