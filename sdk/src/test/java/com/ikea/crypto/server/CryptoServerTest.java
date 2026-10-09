package com.ikea.crypto.server;

import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.stc.crypto.SessionKeyService;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.KeyMetadata;
import com.ikea.crypto.stc.model.PublicKeyResponse;
import com.ikea.crypto.stc.util.EncodingUtils;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import com.ikea.crypto.stc.exception.InvalidCryptoPayloadException;
import com.ikea.crypto.stc.exception.SessionKeyDecryptionException;
import com.ikea.crypto.stc.exception.KeyExpiredException;
import com.ikea.crypto.stc.exception.KeyNotAvailableException;
import com.ikea.crypto.stc.key.KeyRing;
import com.ikea.crypto.stc.key.CryptoServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.*;

class CryptoServerTest {

    private CryptoServer server;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        keyGen.initialize(CryptoConstants.RSA_KEY_SIZE_BITS);
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
        assertEquals(
                response.expiresAtEpochMillis() - server.keyRing().getRotationBeforeExpiryMillis(),
                response.refreshAtEpochMillis()
        );
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
        assertThrows(InvalidCryptoPayloadException.class, () -> server.validatePayload(null));
        assertThrows(InvalidCryptoPayloadException.class, () -> server.validatePayload(
                new CipherRequestPayload(null, "iv", "data")
        ));
        assertThrows(InvalidCryptoPayloadException.class, () -> server.validatePayload(
                new CipherRequestPayload("key", null, "data")
        ));
        assertThrows(InvalidCryptoPayloadException.class, () -> server.validatePayload(
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

        assertThrows(SessionKeyDecryptionException.class, () -> server.decrypt(payload));
    }

    @Test
    void testReturnedPublicKeyMatchesKeyIdPrivateKey() throws Exception {
        PublicKeyResponse response = server.getPublicKey();
        PublicKey publicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA)
                .generatePublic(new X509EncodedKeySpec(EncodingUtils.fromBase64(response.publicKeyBase64())));

        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey sessionKey = keyGenerator.generateKey();
        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, publicKey);

        KeyRing.KeyEntry keyEntry = server.keyRing().findKeyEntry(response.keyId()).orElseThrow();
        SecretKey decrypted = SessionKeyService.decryptSessionKeyBase64(encryptedSessionKey, keyEntry.privateKey());
        assertArrayEquals(sessionKey.getEncoded(), decrypted.getEncoded());
    }

    @Test
    void testExpiredKeyIdReturnsLatestPublicKey() throws Exception {
        KeyRing shortLivedRing = new KeyRing("expired-key", 2, 0);
        shortLivedRing.initialize();
        KeyRing.KeyEntry oldEntry = shortLivedRing.getActiveKeyEntry();
        shortLivedRing.rotateKey();
        shortLivedRing.purgeExpiredKeys(System.currentTimeMillis() + 100);
        CryptoServer rotatingServer = new CryptoServer(shortLivedRing);

        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey sessionKey = keyGenerator.generateKey();
        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(
                sessionKey, oldEntry.publicKey());

        KeyExpiredException exception = assertThrows(KeyExpiredException.class,
                () -> rotatingServer.decryptSessionKeyToSecretKey(
                        oldEntry.metadata().keyId(), encryptedSessionKey));
        assertEquals(shortLivedRing.getActiveKeyEntry().metadata().keyId(), exception.latestKey().keyId());
    }

    @Test
    void automaticRotationCanBeDisabledWhileManualRotationRemainsAvailable() throws Exception {
        String expiredKeyId = "manual-rotation-key:1";
        long now = System.currentTimeMillis();
        KeyMetadata expiredMetadata = new KeyMetadata(expiredKeyId, now - 20_000, now - 10_000);
        KeyRing keyRing = new KeyRing("manual-rotation-key", 60_000, 0, false);
        keyRing.registerKeyEntry(new KeyRing.KeyEntry(expiredMetadata, keyPair), true);
        CryptoServer server = new CryptoServer(keyRing);

        assertThrows(KeyNotAvailableException.class, server::getPublicKey);
        assertThrows(KeyNotAvailableException.class, () -> server.getPublicKey("manual-rotation-key"));
        assertEquals(expiredKeyId, keyRing.getActiveKeyEntry().metadata().keyId());

        PublicKeyResponse rotated = server.rotateKey();
        assertNotEquals(expiredKeyId, rotated.keyId());
        assertEquals(rotated.keyId(), server.getPublicKey().keyId());
        assertEquals(rotated.keyId(), server.getPublicKey("manual-rotation-key").keyId());
    }

    @Test
    void getPublicKeyForAliasAutomaticallyRotatesExpiredKeyWhenEnabled() throws Exception {
        String alias = "automatic-rotation-key";
        long now = System.currentTimeMillis();
        KeyMetadata expiredMetadata = new KeyMetadata(alias + ":1", now - 20_000, now - 10_000);
        KeyRing keyRing = new KeyRing(alias, 60_000, 0);
        keyRing.registerKeyEntry(new KeyRing.KeyEntry(expiredMetadata, keyPair), true);
        CryptoServer server = new CryptoServer(keyRing);

        PublicKeyResponse rotated = server.getPublicKey(alias);

        assertNotEquals(expiredMetadata.keyId(), rotated.keyId());
        assertEquals(rotated.keyId(), keyRing.getActiveKeyEntry().metadata().keyId());
    }

    @Test
    void getPublicKeyRotatesBeforeKeyExpiresWithinConfiguredSafetyWindow() throws Exception {
        String alias = "pre-expiry-rotation-key";
        long now = System.currentTimeMillis();
        KeyMetadata expiringMetadata = new KeyMetadata(alias + ":1", now - 1_000, now + 5_000);
        KeyRing keyRing = new KeyRing(alias, 60_000, 0, true, 10_000);
        keyRing.registerKeyEntry(new KeyRing.KeyEntry(expiringMetadata, keyPair), true);
        CryptoServer server = new CryptoServer(keyRing);

        PublicKeyResponse rotated = server.getPublicKey();

        assertNotEquals(expiringMetadata.keyId(), rotated.keyId());
        assertTrue(rotated.expiresAtEpochMillis() > expiringMetadata.expiresAtEpochMillis());
    }

    @Test
    void getPublicKeyForAliasRotatesBeforeKeyExpiresWithinConfiguredSafetyWindow() throws Exception {
        String alias = "alias-pre-expiry-rotation-key";
        long now = System.currentTimeMillis();
        KeyMetadata expiringMetadata = new KeyMetadata(alias + ":1", now - 1_000, now + 5_000);
        KeyRing keyRing = new KeyRing(alias, 60_000, 0, true, 10_000);
        keyRing.registerKeyEntry(new KeyRing.KeyEntry(expiringMetadata, keyPair), true);
        CryptoServer server = new CryptoServer(keyRing);

        PublicKeyResponse rotated = server.getPublicKey(alias);

        assertNotEquals(expiringMetadata.keyId(), rotated.keyId());
        assertTrue(rotated.expiresAtEpochMillis() > expiringMetadata.expiresAtEpochMillis());
    }

    @Test
    void disabledAutomaticRotationDoesNotRotateWithinSafetyWindow() throws Exception {
        String alias = "manual-pre-expiry-key";
        long now = System.currentTimeMillis();
        KeyMetadata expiringMetadata = new KeyMetadata(alias + ":1", now - 1_000, now + 5_000);
        KeyRing keyRing = new KeyRing(alias, 60_000, 0, false, 10_000);
        keyRing.registerKeyEntry(new KeyRing.KeyEntry(expiringMetadata, keyPair), true);
        CryptoServer server = new CryptoServer(keyRing);

        PublicKeyResponse response = server.getPublicKey();

        assertEquals(expiringMetadata.keyId(), response.keyId());
    }

    @Test
    void retiredKeyGracePeriodStartsAtRotationTime() {
        long day = 24L * 60 * 60 * 1000;
        long hour = 60L * 60 * 1000;
        long createdAt = 1_800_000_000_000L;
        long rotationAt = createdAt + 27 * day + 2 * hour;
        KeyRing keyRing = new KeyRing("scheduled-rotation-key", 30 * day, hour, true, 3 * day);
        KeyRing.KeyEntry oldEntry = new KeyRing.KeyEntry(
                new KeyMetadata("scheduled-rotation-key:1", createdAt, createdAt + 30 * day),
                keyPair
        );
        KeyRing.KeyEntry replacementEntry = new KeyRing.KeyEntry(
                new KeyMetadata("scheduled-rotation-key:2", rotationAt, rotationAt + 30 * day),
                keyPair
        );

        keyRing.registerKeyEntry(oldEntry, true);
        keyRing.registerKeyEntry(replacementEntry, true);

        assertFalse(keyRing.isExpiredBeyondGrace(oldEntry.metadata(), rotationAt + hour - 1));
        assertTrue(keyRing.isExpiredBeyondGrace(oldEntry.metadata(), rotationAt + hour));
        assertFalse(oldEntry.metadata().isExpired(rotationAt + hour));
    }

    @Test
    void keyRingRejectsGracePeriodNotLessThanRotationWindow() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new KeyRing("invalid-timing-key", 60_000, 50_000, true, 50_000)
        );
    }

    @Test
    void testInvalidPayloadForRetainedKeyIsNotReportedAsExpired() throws Exception {
        server.rotateKey();
        assertThrows(SessionKeyDecryptionException.class,
                () -> server.decryptSessionKeyToSecretKey(
                        "in-memory-test-key:1", EncodingUtils.toBase64(new byte[]{1, 2, 3})));
    }
}
