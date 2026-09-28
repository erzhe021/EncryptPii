package com.ikea.crypto.server;

import com.ikea.crypto.common.crypto.AesGcmCryptoService;
import com.ikea.crypto.common.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.crypto.SessionKeyService;
import com.ikea.crypto.common.model.payload.CipherRequestPayload;
import com.ikea.crypto.common.model.payload.PublicKeyResponse;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.server.service.CryptoServer;
import com.ikea.crypto.server.service.KeyRing;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class KeyRotationTest {

    @TempDir
    Path tempDir;

    private CryptoServer server;

    @BeforeEach
    void setUp() throws Exception {
        server = CryptoServer.create(tempDir);
    }

    @Test
    void testInitialKeyGeneration() {
        PublicKeyResponse response = server.getPublicKey();
        assertNotNull(response);
        assertNotNull(response.keyId());
        assertTrue(response.keyId().startsWith("rsa-"));
        assertTrue(response.expiresAtEpochMillis() > System.currentTimeMillis());
    }

    @Test
    void testSmoothRotationAndFallback() throws Exception {
        // 1. Client fetches active Key 1 (old key)
        PublicKeyResponse oldKeyResponse = server.getPublicKey();
        String oldKeyId = oldKeyResponse.keyId();
        PublicKey oldPublicKey = server.publicKey();

        // 2. Client prepares request encrypted with old key (simulate client caching old key)
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey sessionKey = keyGenerator.generateKey();
        byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        String encryptedData = AesGcmCryptoService.encryptAsBase64("data-from-old-client", sessionKey, iv);
        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, oldPublicKey);

        // 3. Server rotates to new Key 2 (simulating 1-year periodic rotation)
        KeyRing.KeyEntry newKeyEntry = server.keyRing().rotateKey();
        String newKeyId = newKeyEntry.metadata().keyId();
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
        String newEncryptedData = AesGcmCryptoService.encryptAsBase64("data-from-new-client", newSessionKey, newIv);
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
}
