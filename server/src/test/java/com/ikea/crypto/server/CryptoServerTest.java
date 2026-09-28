package com.ikea.crypto.server;

import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.crypto.AesGcmCipher;
import com.ikea.crypto.common.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.crypto.SessionKeyService;
import com.ikea.crypto.common.model.payload.CipherRequestPayload;
import com.ikea.crypto.common.model.payload.PublicKeyResponse;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.service.CryptoServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class CryptoServerTest {

    private CryptoServer server;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();

        server = new CryptoServer(keyPair.getPrivate(), keyPair.getPublic());
    }

    @AfterEach
    void tearDown() {
        CryptoSessionContextAccessor.clearCryptoSessionContext();
    }

    @Test
    void testGetPublicKey() {
        PublicKeyResponse response = server.getPublicKey();
        assertNotNull(response);
        assertNotNull(response.publicKeyBase64());
        assertEquals("in-memory-test-key:1", response.keyId());
        assertTrue(response.expiresAtEpochMillis() > System.currentTimeMillis());
    }

    @Test
    void testDecryptValidPayload() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey sessionKey = keyGenerator.generateKey();

        byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        String plaintext = "Secret Message from Client";

        String encryptedData = AesGcmCipher.encryptAsBase64(plaintext, sessionKey, iv);
        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, keyPair.getPublic());

        CipherRequestPayload payload = new CipherRequestPayload(
                encryptedSessionKey,
                EncodingUtils.toBase64(iv),
                encryptedData
        );

        String decrypted = server.decrypt(payload);
        assertEquals(plaintext, decrypted);

        // Verify resolved session key was set in request context
        SecretKey resolvedKey = CryptoSessionContextAccessor.getResolvedSessionKey();
        assertNotNull(resolvedKey);
        assertArrayEquals(sessionKey.getEncoded(), resolvedKey.getEncoded());
    }

    @Test
    void testValidatePayloadRejectsMissingFields() {
        assertThrows(IllegalArgumentException.class, () -> server.validatePayload(null));
        assertThrows(IllegalArgumentException.class, () -> server.validatePayload(
                new CipherRequestPayload(null, "iv", "data")
        ));
        assertThrows(IllegalArgumentException.class, () -> server.validatePayload(
                new CipherRequestPayload("key", null, "data")
        ));
        assertThrows(IllegalArgumentException.class, () -> server.validatePayload(
                new CipherRequestPayload("key", "iv", null)
        ));
    }

    @Test
    void testDecryptFailsWithInvalidKey() {
        CipherRequestPayload payload = new CipherRequestPayload(
                EncodingUtils.toBase64(new byte[]{1, 2, 3}),
                EncodingUtils.toBase64(new byte[12]),
                EncodingUtils.toBase64(new byte[]{4, 5, 6})
        );

        assertThrows(GeneralSecurityException.class, () -> server.decrypt(payload));
    }
}
