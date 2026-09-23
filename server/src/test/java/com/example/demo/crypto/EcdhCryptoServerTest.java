package com.example.demo.crypto;

import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhCryptoClient;
import com.example.demo.crypto.ecdh.EcdhPublicKeyResponse;
import com.example.demo.server.crypto.ecdh.EcdhCryptoServer;
import com.github.benmanes.caffeine.cache.Cache;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

class EcdhCryptoServerTest {

    @Test
    void decryptShouldInvalidateEphemeralPrivateKeyAfterSuccessfulUse() throws Exception {
        Path tempDir = Files.createTempDirectory("ecdh-server-test");
        EcdhCryptoServer server = EcdhCryptoServer.create(tempDir);
        EcdhPublicKeyResponse response = server.generateEphemeralEcdhPublicKey();

        EcdhCryptoClient client = new EcdhCryptoClient(() -> response);
        EcdhCipherPayload payload = client.encrypt("13800138000");

        assertEquals("13800138000", server.decryptEcdhData(payload));

        Field field = EcdhCryptoServer.class.getDeclaredField("ephemeralEcdhPrivateKeys");
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
        EcdhCryptoServer baselineServer = EcdhCryptoServer.create(tempDir);
        EcdhCryptoServer server = new EcdhCryptoServer(
                baselineServer.getLongTermIdentityPrivateKey(),
                baselineServer.getLongTermIdentityPublicKey(),
                Duration.ofMillis(1),
                EcdhCryptoServer.DEFAULT_MAX_EPHEMERAL_KEYS
        );
        EcdhPublicKeyResponse response = server.generateEphemeralEcdhPublicKey();
        EcdhCryptoClient client = new EcdhCryptoClient(() -> response);
        EcdhCipherPayload payload = client.encrypt("13800138000");

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
        EcdhCryptoServer baselineServer = EcdhCryptoServer.create(tempDir);
        EcdhCryptoServer server = new EcdhCryptoServer(
                baselineServer.getLongTermIdentityPrivateKey(),
                baselineServer.getLongTermIdentityPublicKey(),
                EcdhCryptoServer.DEFAULT_EPHEMERAL_KEY_TTL,
                1
        );

        EcdhPublicKeyResponse first = server.generateEphemeralEcdhPublicKey();
        EcdhPublicKeyResponse second = server.generateEphemeralEcdhPublicKey();

        Field field = EcdhCryptoServer.class.getDeclaredField("ephemeralEcdhPrivateKeys");
        field.setAccessible(true);
        @SuppressWarnings("unchecked")
        Cache<String, ?> privateKeys = (Cache<String, ?>) field.get(server);
        privateKeys.cleanUp();

        assertFalse(privateKeys.asMap().containsKey(first.ephemeralPublicKeyBase64()));
        assertEquals(1, privateKeys.estimatedSize());
        assertEquals(second.ephemeralPublicKeyBase64(), privateKeys.asMap().keySet().iterator().next());
    }
}
