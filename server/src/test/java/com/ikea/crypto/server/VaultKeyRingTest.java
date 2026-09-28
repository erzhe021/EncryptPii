package com.ikea.crypto.server;

import com.ikea.crypto.common.crypto.AesGcmCipher;
import com.ikea.crypto.common.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.crypto.SessionKeyService;
import com.ikea.crypto.common.model.payload.CipherRequestPayload;
import com.ikea.crypto.common.model.payload.PublicKeyResponse;
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
}
