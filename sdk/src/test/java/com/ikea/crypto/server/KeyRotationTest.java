package com.ikea.crypto.server;

import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.stc.crypto.SessionKeyService;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.PublicKeyResponse;
import com.ikea.crypto.stc.util.EncodingUtils;
import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.key.KeyRing;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class KeyRotationTest {

    private CryptoServer server;

    @BeforeEach
    void setUp() throws Exception {
        KeyRing keyRing = new KeyRing();
        keyRing.initialize();
        server = new CryptoServer(keyRing);
    }

    @Test
    void testInitialKeyGeneration() {
        PublicKeyResponse response = server.getPublicKey();
        assertNotNull(response);
        assertNotNull(response.keyId());
        assertEquals("ciam:1", response.keyId());
        assertTrue(response.keyId().matches("^[a-zA-Z0-9_-]+:\\d+$"));
        assertTrue(response.expiresAtEpochMillis() > System.currentTimeMillis());
    }

    @Test
    void testSmoothRotationAndFallback() throws Exception {
        // 1. Client fetches active Key 1 (old key)
        PublicKeyResponse oldKeyResponse = server.getPublicKey();
        String oldKeyId = oldKeyResponse.keyId();
        assertEquals("ciam:1", oldKeyId);
        PublicKey oldPublicKey = server.publicKey();

        // 2. Client prepares request encrypted with old key (simulate client caching old key)
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey sessionKey = keyGenerator.generateKey();
        byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        String encryptedData = AesGcmCipher.encryptAsBase64("data-from-old-client", sessionKey, iv);
        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, oldPublicKey);

        // 3. Server rotates to new Key 2 (simulating 1-year periodic rotation)
        KeyRing.KeyEntry newKeyEntry = server.keyRing().rotateKey();
        String newKeyId = newKeyEntry.metadata().keyId();
        assertEquals("ciam:2", newKeyId);
        assertNotEquals(oldKeyId, newKeyId);
        assertEquals(newKeyId, server.getPublicKey().keyId());

        // 4. Client sends payload encrypted with old key, explicitly specifying oldKeyId
        CipherRequestPayload payloadWithOldKeyId = new CipherRequestPayload(
                oldKeyId,
                encryptedSessionKey,
                EncodingUtils.toBase64(iv),
                encryptedData
        );
        String decrypted = server.decrypt(payloadWithOldKeyId);
        assertEquals("data-from-old-client", decrypted);

        // 5. Client sends payload encrypted with old key, WITHOUT specifying keyId (fallback to transition keys in keyring)
        CipherRequestPayload payloadWithoutKeyId = new CipherRequestPayload(
                null,
                encryptedSessionKey,
                EncodingUtils.toBase64(iv),
                encryptedData
        );
        String decryptedFallback = server.decrypt(payloadWithoutKeyId);
        assertEquals("data-from-old-client", decryptedFallback);

        // 6. Client encrypts with new key - decrypted successfully as well
        SecretKey newSessionKey = keyGenerator.generateKey();
        byte[] newIv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        String newEncryptedData = AesGcmCipher.encryptAsBase64("data-from-new-client", newSessionKey, newIv);
        String newEncryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(newSessionKey, newKeyEntry.publicKey());

        CipherRequestPayload payloadWithNewKey = new CipherRequestPayload(
                newKeyId,
                newEncryptedSessionKey,
                EncodingUtils.toBase64(newIv),
                newEncryptedData
        );
        String decryptedNew = server.decrypt(payloadWithNewKey);
        assertEquals("data-from-new-client", decryptedNew);
    }

    @Test
    void testCustomKeyAliasAndSequentialVersions() throws Exception {
        KeyRing customRing = new KeyRing("my-service-key");
        customRing.initialize();

        assertEquals("my-service-key:1", customRing.getActiveKeyEntry().metadata().keyId());
        assertEquals("my-service-key", customRing.getActiveKeyEntry().metadata().keyAlias());
        assertEquals(1L, customRing.getActiveKeyEntry().metadata().version());

        KeyRing.KeyEntry v2 = customRing.rotateKey();
        assertEquals("my-service-key:2", v2.metadata().keyId());
        assertEquals(2L, v2.metadata().version());

        KeyRing.KeyEntry v3 = customRing.rotateKey();
        assertEquals("my-service-key:3", v3.metadata().keyId());
        assertEquals(3L, v3.metadata().version());
    }

    @Test
    void testRotateKeyWithSpecifiedKeyAlias() throws Exception {
        long now = System.currentTimeMillis();
        KeyRing keyRing = new KeyRing("default-app-key");
        keyRing.initialize();
        assertEquals("default-app-key:1", keyRing.getActiveKeyEntry().metadata().keyId());

        // Rotate for a different keyAlias
        KeyRing.KeyEntry orderV1 = keyRing.rotateKey("order-key");
        assertEquals("order-key:1", orderV1.metadata().keyId());
        assertEquals("order-key", orderV1.metadata().keyAlias());
        assertEquals(1L, orderV1.metadata().version());
        assertEquals("order-key:1", keyRing.getActiveKeyEntry().metadata().keyId());

        // Rotate for order-key again -> version 2
        KeyRing.KeyEntry orderV2 = keyRing.rotateKey("order-key");
        assertEquals("order-key:2", orderV2.metadata().keyId());
        assertEquals(2L, orderV2.metadata().version());

        // Rotate back for default-app-key -> version 2
        KeyRing.KeyEntry defaultV2 = keyRing.rotateKey("default-app-key");
        assertEquals("default-app-key:2", defaultV2.metadata().keyId());
        assertEquals(2L, defaultV2.metadata().version());

        // Verify findActiveKeyEntry for both aliases
        assertTrue(keyRing.findActiveKeyEntry("order-key").isPresent());
        assertEquals("order-key:2", keyRing.findActiveKeyEntry("order-key").get().metadata().keyId());

        assertTrue(keyRing.findActiveKeyEntry("default-app-key").isPresent());
        assertEquals("default-app-key:2", keyRing.findActiveKeyEntry("default-app-key").get().metadata().keyId());
    }
}
