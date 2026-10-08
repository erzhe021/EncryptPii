package com.ikea.crypto.server;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.stc.crypto.SessionKeyService;
import com.ikea.crypto.stc.model.CipherResponsePayload;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.CipherRequestBody;
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
import java.net.URI;
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

        String jsonPayload = objectMapper.writeValueAsString(
                new CipherRequestBody(EncodingUtils.toBase64(iv), encryptedData));

        CryptoSessionContext context = payloadHandler.createSessionContext(
                jsonPayload, "in-memory-test-key:1", encryptedSessionKey);
        String decrypted = payloadHandler.decrypt(context);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void testCreateSessionContextRejectsKeyMaterialInBody() throws Exception {
        String oldBody = objectMapper.writeValueAsString(new CipherRequestPayload(
                "key-id", "wrapped-key", "iv", "data"));
        assertThrows(InvalidCryptoPayloadException.class, () ->
                payloadHandler.createSessionContext(oldBody, "in-memory-test-key:1", "wrapped-key"));
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

    @Test
    void testSessionKeyTransportUsesRequiredStcHeaders() {
        SessionKeyTransport transport = new SessionKeyTransport("ciam:1", "wrapped-key");
        var request = transport.apply(java.net.http.HttpRequest.newBuilder(URI.create("https://example.test")))
                .build();
        assertEquals("ciam:1", request.headers()
                .firstValue(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_KEY_ID).orElseThrow());
        assertEquals("wrapped-key", request.headers()
                .firstValue(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_SESSION_KEY).orElseThrow());
        assertThrows(IllegalArgumentException.class, () ->
                new SessionKeyTransport(null, "wrapped-key").apply(
                        java.net.http.HttpRequest.newBuilder(URI.create("https://example.test"))));
    }
}
