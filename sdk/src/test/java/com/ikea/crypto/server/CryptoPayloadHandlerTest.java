package com.ikea.crypto.server;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.stc.crypto.SessionKeyService;
import com.ikea.crypto.stc.model.CipherResponsePayload;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.SessionKeyTransport;
import com.ikea.crypto.stc.util.EncodingUtils;
import com.ikea.crypto.stc.web.codec.CryptoPayloadHandler;
import com.ikea.crypto.stc.session.CryptoSessionContext;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import com.ikea.crypto.stc.exception.InvalidCryptoPayloadException;
import com.ikea.crypto.stc.key.CryptoServer;
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
        CryptoSessionContextAccessor.clearCryptoSessionContext();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        keyGen.initialize(CryptoConstants.RSA_KEY_SIZE_BITS);
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

        String encryptedData = AesGcmCipher.encryptAsBase64(plaintext, sessionKey, iv);
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
        String decrypted = AesGcmCipher.decryptFromBase64(
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

        String decrypted = AesGcmCipher.decryptFromBase64(
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
