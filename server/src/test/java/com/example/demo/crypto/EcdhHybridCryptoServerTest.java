package com.example.demo.crypto;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import com.github.benmanes.caffeine.cache.Cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EcdhHybridCryptoServerTest {

    @Test
    void decryptShouldInvalidateEphemeralPrivateKeyAfterSuccessfulUse() throws Exception {
        Path tempDir = Files.createTempDirectory("ecdh-server-test");
        EcdhHybridCryptoServer server = EcdhHybridCryptoServer.create(tempDir);
        EcdhPublicKeyResponse response = server.generateEphemeralEcdhPublicKey();

        EcdhHybridCryptoClient client = new EcdhHybridCryptoClient(() -> response);
        EcdhHybridCipherPayload payload = client.encrypt("13800138000");

        assertEquals("13800138000", server.decryptEcdhData(payload));

        Field field = EcdhHybridCryptoServer.class.getDeclaredField("ephemeralEcdhPrivateKeys");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        Cache<String, ?> privateKeys = (Cache<String, ?>) field.get(server);
        assertFalse(privateKeys.asMap().containsKey(response.ephemeralPublicKeyBase64()));

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> server.decryptEcdhData(payload)
        );
        assertEquals(
                "No matching ephemeral server private key found for this ECDH request. Session key generation must use a fresh ephemeral key pair only.",
                ex.getMessage()
        );
    }

    @Test
    void decryptShouldRejectExpiredEphemeralPrivateKey() throws Exception {
        Path tempDir = Files.createTempDirectory("ecdh-server-expire-test");
        EcdhHybridCryptoServer baselineServer = EcdhHybridCryptoServer.create(tempDir);
        EcdhHybridCryptoServer server = new EcdhHybridCryptoServer(
                baselineServer.getLongTermIdentityPrivateKey(),
                baselineServer.getLongTermIdentityPublicKey(),
                Duration.ofMillis(1),
                EcdhHybridCryptoServer.DEFAULT_MAX_EPHEMERAL_KEYS
        );
        EcdhPublicKeyResponse response = server.generateEphemeralEcdhPublicKey();
        EcdhHybridCryptoClient client = new EcdhHybridCryptoClient(() -> response);
        EcdhHybridCipherPayload payload = client.encrypt("13800138000");

        Thread.sleep(20L);

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> server.decryptEcdhData(payload)
        );
        assertEquals(
                "No matching ephemeral server private key found for this ECDH request. Session key generation must use a fresh ephemeral key pair only.",
                ex.getMessage()
        );
    }

    @Test
    void generateEphemeralEcdhPublicKeyShouldEvictOldKeysWhenCacheIsFull() throws Exception {
        Path tempDir = Files.createTempDirectory("ecdh-server-capacity-test");
        EcdhHybridCryptoServer baselineServer = EcdhHybridCryptoServer.create(tempDir);
        EcdhHybridCryptoServer server = new EcdhHybridCryptoServer(
                baselineServer.getLongTermIdentityPrivateKey(),
                baselineServer.getLongTermIdentityPublicKey(),
                EcdhHybridCryptoServer.DEFAULT_EPHEMERAL_KEY_TTL,
                1
        );

        EcdhPublicKeyResponse first = server.generateEphemeralEcdhPublicKey();
        EcdhPublicKeyResponse second = server.generateEphemeralEcdhPublicKey();

        Field field = EcdhHybridCryptoServer.class.getDeclaredField("ephemeralEcdhPrivateKeys");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        Cache<String, ?> privateKeys = (Cache<String, ?>) field.get(server);
        privateKeys.cleanUp();

        assertFalse(privateKeys.asMap().containsKey(first.ephemeralPublicKeyBase64()));
        assertEquals(1, privateKeys.estimatedSize());
        assertEquals(second.ephemeralPublicKeyBase64(), privateKeys.asMap().keySet().iterator().next());
    }
}
