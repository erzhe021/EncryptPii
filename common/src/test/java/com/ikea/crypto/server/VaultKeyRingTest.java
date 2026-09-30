package com.ikea.crypto.server;

import com.ikea.crypto.common.crypto.AesGcmCipher;
import com.ikea.crypto.common.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.crypto.SessionKeyService;
import com.ikea.crypto.common.model.CipherRequestPayload;
import com.ikea.crypto.common.model.PublicKeyResponse;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.server.service.CryptoServer;
import com.ikea.crypto.server.service.KeyRing;
import com.ikea.crypto.server.vault.VaultClient;
import com.ikea.crypto.server.vault.VaultKeyRing;
import com.ikea.crypto.server.vault.VaultProperties;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

public class VaultKeyRingTest {

    private static final String VAULT_ADDR = "http://127.0.0.1:8200";
    private static boolean vaultAvailable = false;

    @BeforeAll
    static void checkVaultAvailable() {
        try {
            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(VAULT_ADDR + "/v1/sys/health"))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            vaultAvailable = (response.statusCode() == 200 || response.statusCode() == 429);
        } catch (Exception e) {
            vaultAvailable = false;
        }
    }

    @Test
    void testVaultKeyGenerationAndRotationLifecycle() throws Exception {
        Assumptions.assumeTrue(vaultAvailable, "Skipping test because Vault is not running at " + VAULT_ADDR);

        VaultProperties properties = new VaultProperties();
        properties.setEnabled(true);
        properties.setAddr(VAULT_ADDR);
        properties.setAuthMethod(VaultProperties.AuthMethod.TOKEN);
        properties.setToken("root");
        properties.setSecretPath("secret/data/crypto/lifecycle-test-keys");
        properties.setAutoBootstrap(true);

        VaultClient vaultClient = new VaultClient(VAULT_ADDR);

        // 1. Initialize VaultKeyRing - automatically generates initial RSA key in Vault
        VaultKeyRing vaultKeyRing = new VaultKeyRing(properties, vaultClient);
        vaultKeyRing.initialize();
        CryptoServer server = new CryptoServer(vaultKeyRing);

        PublicKeyResponse initialKey = server.getPublicKey();
        assertNotNull(initialKey);
        assertNotNull(initialKey.keyId());
        String oldKeyId = initialKey.keyId();
        PublicKey oldPublicKey = server.publicKey();

        // 2. Client prepares request encrypted with old key (simulating client with cached public key)
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey sessionKey = keyGenerator.generateKey();
        byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        String encryptedData = AesGcmCipher.encryptAsBase64("vault-data-before-rotation", sessionKey, iv);
        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, oldPublicKey);

        // 3. Trigger rotation in Vault: new key is generated and persisted to Vault KV v2
        KeyRing.KeyEntry rotatedEntry = vaultKeyRing.rotateKey();
        String newKeyId = rotatedEntry.metadata().keyId();
        assertNotEquals(oldKeyId, newKeyId);
        assertEquals(newKeyId, server.getPublicKey().keyId());

        // 4. Server successfully decrypts request encrypted with old key (grace period fallback)
        CipherRequestPayload oldPayloadWithId = new CipherRequestPayload(
                oldKeyId,
                encryptedSessionKey,
                EncodingUtils.toBase64(iv),
                encryptedData
        );
        String decryptedOld = server.decrypt(oldPayloadWithId);
        assertEquals("vault-data-before-rotation", decryptedOld);

        // 5. New client encrypts request with the newly rotated key
        String newEncryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, server.publicKey());
        String newEncryptedData = AesGcmCipher.encryptAsBase64("vault-data-after-rotation", sessionKey, iv);
        CipherRequestPayload newPayload = new CipherRequestPayload(
                newKeyId,
                newEncryptedSessionKey,
                EncodingUtils.toBase64(iv),
                newEncryptedData
        );
        String decryptedNew = server.decrypt(newPayload);
        assertEquals("vault-data-after-rotation", decryptedNew);

        // 6. Simulate another pod starting up: loads active and transition keys from Vault
        VaultKeyRing anotherPodKeyRing = new VaultKeyRing(properties, vaultClient);
        anotherPodKeyRing.initialize();
        assertEquals(newKeyId, anotherPodKeyRing.getActiveKeyEntry().metadata().keyId());
        assertTrue(anotherPodKeyRing.findKeyEntry(oldKeyId).isPresent());
    }

    @Test
    void testRotateKeyFetchesAuthoritativeVersionFromVault() throws Exception {
        Assumptions.assumeTrue(vaultAvailable, "Skipping test because Vault is not running at " + VAULT_ADDR);

        String testAlias = "multi-pod-" + java.util.UUID.randomUUID().toString().substring(0, 8);
        VaultProperties properties = new VaultProperties();
        properties.setEnabled(true);
        properties.setAddr(VAULT_ADDR);
        properties.setAuthMethod(VaultProperties.AuthMethod.TOKEN);
        properties.setToken("root");
        properties.setSecretPath("secret/data/crypto/" + testAlias);
        properties.setKeyAlias(testAlias);
        properties.setAutoBootstrap(true);

        VaultClient vaultClient = new VaultClient(VAULT_ADDR);

        // Pod 1 starts and initializes v1
        VaultKeyRing pod1 = new VaultKeyRing(properties, vaultClient);
        pod1.initialize();
        assertEquals(testAlias + ":1", pod1.getActiveKeyEntry().metadata().keyId());

        // Pod 2 starts and initializes v1
        VaultKeyRing pod2 = new VaultKeyRing(properties, vaultClient);
        pod2.initialize();
        assertEquals(testAlias + ":1", pod2.getActiveKeyEntry().metadata().keyId());

        // Pod 1 rotates to v2 in Vault
        KeyRing.KeyEntry pod1V2 = pod1.rotateKey();
        assertEquals(testAlias + ":2", pod1V2.metadata().keyId());

        // Pod 1 rotates again to v3 in Vault
        KeyRing.KeyEntry pod1V3 = pod1.rotateKey();
        assertEquals(testAlias + ":3", pod1V3.metadata().keyId());

        // Pod 2's local memory only knows v1 (it never heard about v2 and v3).
        // With Double-Checked Refresh, Pod 2 checks Vault first, finds valid unexpired v3,
        // and synchronizes v3 without generating or writing a new key (no v4 is created).
        KeyRing.KeyEntry pod2Rotated = pod2.rotateKey();
        assertEquals(testAlias + ":3", pod2Rotated.metadata().keyId());
        assertEquals(3L, pod2Rotated.metadata().version());

        // When force rotate is explicitly requested, Pod 2 bypasses double-check and rotates to v4
        KeyRing.KeyEntry pod2ForceRotated = pod2.forceRotateKey(testAlias);
        assertEquals(testAlias + ":4", pod2ForceRotated.metadata().keyId());
        assertEquals(4L, pod2ForceRotated.metadata().version());
    }

    @Test
    void testConcurrentPodsCasContention() throws Exception {
        Assumptions.assumeTrue(vaultAvailable, "Skipping test because Vault is not running at " + VAULT_ADDR);

        String testAlias = "cas-race-" + java.util.UUID.randomUUID().toString().substring(0, 8);
        VaultProperties properties = new VaultProperties();
        properties.setEnabled(true);
        properties.setAddr(VAULT_ADDR);
        properties.setAuthMethod(VaultProperties.AuthMethod.TOKEN);
        properties.setToken("root");
        properties.setSecretPath("secret/data/crypto/" + testAlias);
        properties.setKeyAlias(testAlias);
        properties.setAutoBootstrap(true);
        properties.setCasBackoffMillis(300L); // Fast backoff for test

        VaultClient vaultClient = new VaultClient(VAULT_ADDR);

        // Bootstrap initial version 1
        VaultKeyRing pod1 = new VaultKeyRing(properties, vaultClient);
        pod1.initialize();
        assertEquals(testAlias + ":1", pod1.getActiveKeyEntry().metadata().keyId());

        VaultKeyRing pod2 = new VaultKeyRing(properties, vaultClient);
        pod2.initialize();
        assertEquals(testAlias + ":1", pod2.getActiveKeyEntry().metadata().keyId());

        // Concurrently trigger rotation on both Pod 1 and Pod 2 (both force-rotate to trigger CAS competition)
        java.util.concurrent.CyclicBarrier barrier = new java.util.concurrent.CyclicBarrier(2);
        java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors.newFixedThreadPool(2);

        java.util.concurrent.Future<KeyRing.KeyEntry> f1 = executor.submit(() -> {
            barrier.await();
            return pod1.forceRotateKey(testAlias);
        });

        java.util.concurrent.Future<KeyRing.KeyEntry> f2 = executor.submit(() -> {
            barrier.await();
            return pod2.forceRotateKey(testAlias);
        });

        KeyRing.KeyEntry res1 = f1.get(10, java.util.concurrent.TimeUnit.SECONDS);
        KeyRing.KeyEntry res2 = f2.get(10, java.util.concurrent.TimeUnit.SECONDS);
        executor.shutdown();

        // Both pods must have successfully obtained valid keys
        assertNotNull(res1);
        assertNotNull(res2);

        // One of them won CAS (e.g. v2) and the other either waited and fetched v2 or competed sequentially
        // Verify Vault's latest version matches the active keys in both pods
        var latestInVault = vaultClient.readSecretVersion("root", "secret/data/crypto/" + testAlias, null);
        assertTrue(latestInVault.isPresent());
        int vaultVersion = latestInVault.get().version();
        assertTrue(vaultVersion >= 2, "Vault version must be at least 2");

        // Active key in both pods can decrypt each other's payloads
        assertEquals(pod1.getActiveKeyEntry().metadata().version(), pod2.getActiveKeyEntry().metadata().version());
    }

    @Test
    void testDoubleCheckedRefreshWhenKeyExpiredOnOtherPods() throws Exception {
        Assumptions.assumeTrue(vaultAvailable, "Skipping test because Vault is not running at " + VAULT_ADDR);

        String testAlias = "expire-sync-" + java.util.UUID.randomUUID().toString().substring(0, 8);
        VaultProperties properties = new VaultProperties();
        properties.setEnabled(true);
        properties.setAddr(VAULT_ADDR);
        properties.setAuthMethod(VaultProperties.AuthMethod.TOKEN);
        properties.setToken("root");
        properties.setSecretPath("secret/data/crypto/" + testAlias);
        properties.setKeyAlias(testAlias);
        properties.setAutoBootstrap(true);
        properties.setValidityMillis(500L); // Expires in 500ms
        properties.setGracePeriodMillis(5000L);

        VaultClient vaultClient = new VaultClient(VAULT_ADDR);

        // Pod 1 & Pod 2 both start up with version 1
        VaultKeyRing pod1 = new VaultKeyRing(properties, vaultClient);
        pod1.initialize();
        CryptoServer server1 = new CryptoServer(pod1);

        VaultKeyRing pod2 = new VaultKeyRing(properties, vaultClient);
        pod2.initialize();
        CryptoServer server2 = new CryptoServer(pod2);

        assertEquals(testAlias + ":1", server1.getPublicKey().keyId());
        assertEquals(testAlias + ":1", server2.getPublicKey().keyId());

        // Wait for key to expire on both pods
        Thread.sleep(600L);

        // Pod 1 detects expiration first upon getPublicKey, rotates to v2 in Vault
        PublicKeyResponse key1 = server1.getPublicKey();
        assertEquals(testAlias + ":2", key1.keyId());

        // Pod 2 now calls getPublicKey: its local memory has expired v1, BUT Vault already has v2.
        // Double-Checked Refresh must kick in: Pod 2 syncs v2, DOES NOT rotate, Vault stays at v2!
        PublicKeyResponse key2 = server2.getPublicKey();
        assertEquals(testAlias + ":2", key2.keyId());
        assertEquals(key1.publicKeyBase64(), key2.publicKeyBase64(), "Pod 2 must reuse the same key generated by Pod 1");

        // Verify Vault version is strictly 2 (Pod 2 did NOT generate v3)
        var latestInVault = vaultClient.readSecretVersion("root", "secret/data/crypto/" + testAlias, null);
        assertTrue(latestInVault.isPresent());
        assertEquals(2, latestInVault.get().version(), "Vault version must remain 2; Pod 2 did not perform rotation");
    }

    @Test
    void testCacheMissOnDemandFetchFromVaultWhenOtherPodRotated() throws Exception {
        Assumptions.assumeTrue(vaultAvailable, "Skipping test because Vault is not running at " + VAULT_ADDR);

        String testAlias = "cache-miss-" + java.util.UUID.randomUUID().toString().substring(0, 8);
        VaultProperties properties = new VaultProperties();
        properties.setEnabled(true);
        properties.setAddr(VAULT_ADDR);
        properties.setAuthMethod(VaultProperties.AuthMethod.TOKEN);
        properties.setToken("root");
        properties.setSecretPath("secret/data/crypto/" + testAlias);
        properties.setKeyAlias(testAlias);
        properties.setAutoBootstrap(true);

        VaultClient vaultClient = new VaultClient(VAULT_ADDR);

        // 1. Pod 1 and Pod 2 start with version 1
        VaultKeyRing pod1 = new VaultKeyRing(properties, vaultClient);
        pod1.initialize();
        CryptoServer server1 = new CryptoServer(pod1);

        VaultKeyRing pod2 = new VaultKeyRing(properties, vaultClient);
        pod2.initialize();
        CryptoServer server2 = new CryptoServer(pod2);

        assertEquals(testAlias + ":1", server1.getPublicKey().keyId());
        assertEquals(testAlias + ":1", server2.getPublicKey().keyId());

        // 2. Pod 1 force-rotates to version 2 in Vault
        KeyRing.KeyEntry pod1V2 = pod1.forceRotateKey(testAlias);
        assertEquals(testAlias + ":2", pod1V2.metadata().keyId());
        assertEquals(testAlias + ":2", server1.getPublicKey().keyId());

        // Pod 2 is completely unaware of v2; its local memory only has v1
        assertEquals(1L, pod2.getActiveKeyEntry().metadata().version());

        // 3. Client gets v2 public key from Pod 1 and encrypts sensitive payload
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey sessionKey = keyGenerator.generateKey();
        byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        String encryptedData = AesGcmCipher.encryptAsBase64("secret-data-for-pod2", sessionKey, iv);
        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, pod1V2.publicKey());

        CipherRequestPayload payloadWithV2 = new CipherRequestPayload(
                testAlias + ":2",
                encryptedSessionKey,
                EncodingUtils.toBase64(iv),
                encryptedData
        );

        // 4. Client sends payload to Pod 2!
        // Pod 2 triggers Cache Miss On-Demand: automatically fetches v2 from Vault,
        // caches v2 in local memory, and decrypts successfully!
        String decrypted = server2.decrypt(payloadWithV2);
        assertEquals("secret-data-for-pod2", decrypted);

        // 5. Verify Pod 2 now has v2 cached and promoted to active in memory
        assertTrue(pod2.findKeyEntry(testAlias + ":2").isPresent());
        assertEquals(2L, pod2.getActiveKeyEntry().metadata().version());
    }
}
