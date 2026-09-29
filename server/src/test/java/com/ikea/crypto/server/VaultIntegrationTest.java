package com.ikea.crypto.server;

import com.ikea.crypto.common.crypto.AesGcmCipher;
import com.ikea.crypto.common.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.crypto.SessionKeyService;
import com.ikea.crypto.common.model.CipherRequestPayload;
import com.ikea.crypto.common.model.PublicKeyResponse;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.server.service.CryptoServer;
import com.ikea.crypto.server.service.KeyRing;
import com.ikea.crypto.server.vault.VaultKeySynchronizer;
import com.ikea.crypto.server.vault.VaultProperties;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;

import lombok.extern.slf4j.Slf4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@Slf4j
public class VaultIntegrationTest {

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
    void testVaultTokenAuthAndLocalDecryption() throws Exception {
        Assumptions.assumeTrue(vaultAvailable, "Skipping test because Vault is not running at " + VAULT_ADDR);

        VaultProperties props = new VaultProperties();
        props.setEnabled(true);
        props.setAddr(VAULT_ADDR);
        props.setAuthMethod(VaultProperties.AuthMethod.TOKEN);
        props.setToken("root");
        props.setSecretPath("secret/data/crypto/demo-keys");
        props.setAutoBootstrap(true);

        VaultKeySynchronizer synchronizer = new VaultKeySynchronizer(props);
        KeyRing keyRing = synchronizer.syncToKeyRing();
        CryptoServer server = new CryptoServer(keyRing);

        // Client fetches public key
        PublicKeyResponse pubKeyResponse = server.getPublicKey();
        assertNotNull(pubKeyResponse.publicKeyBase64());
        assertNotNull(pubKeyResponse.keyId());

        // Client encrypts sensitive data
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey sessionKey = keyGen.generateKey();
        byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());

        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, server.publicKey());
        String encryptedData = AesGcmCipher.encryptAsBase64("Sensitive-Vault-Data-123456", sessionKey, iv);

        CipherRequestPayload payload = new CipherRequestPayload(
                pubKeyResponse.keyId(),
                encryptedSessionKey,
                EncodingUtils.toBase64(iv),
                encryptedData
        );

        // Server decrypts locally without network calls to Vault
        String decrypted = server.decrypt(payload);
        assertEquals("Sensitive-Vault-Data-123456", decrypted);
    }

    @Test
    void testVaultKubernetesAuthAndLocalDecryption() throws Exception {
        // Start a mock Vault server locally to simulate Vault's K8s Auth and KV v2 responses
        HttpServer mockVault = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        int vaultPort = mockVault.getAddress().getPort();
        String mockVaultAddr = "http://127.0.0.1:" + vaultPort;

        // Generate RSA key pair for the test
        java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        java.security.KeyPair keyPair = kpg.generateKeyPair();
        String pubBase64 = EncodingUtils.toBase64(keyPair.getPublic().getEncoded());
        String privBase64 = EncodingUtils.toBase64(keyPair.getPrivate().getEncoded());

        // Handle Vault Kubernetes Login: POST /v1/auth/kubernetes/login
        mockVault.createContext("/v1/auth/kubernetes/login", exchange -> {
            log.info("Mock Vault received K8s login request");
            String response = """
                    {
                      "auth": {
                        "client_token": "s.k8s-authed-vault-token-12345",
                        "policies": ["crypto-policy"],
                        "lease_duration": 3600
                      }
                    }
                    """;
            byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });

        // Handle Vault KV v2 Read: GET /v1/secret/data/crypto/k8s-keys
        mockVault.createContext("/v1/secret/data/crypto/k8s-keys", exchange -> {
            log.info("Mock Vault received secret read request with X-Vault-Token: {}",
                    exchange.getRequestHeaders().getFirst("X-Vault-Token"));
            String response = String.format("""
                    {
                      "data": {
                        "data": {
                          "publicKey": "%s",
                          "privateKey": "%s"
                        },
                        "metadata": {
                          "version": 1,
                          "created_time": "2026-09-28T12:00:00Z"
                        }
                      }
                    }
                    """, pubBase64, privBase64);
            byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });

        mockVault.start();

        try {
            // Configure VaultProperties for Kubernetes Authentication
            VaultProperties props = new VaultProperties();
            props.setEnabled(true);
            props.setAddr(mockVaultAddr);
            props.setAuthMethod(VaultProperties.AuthMethod.KUBERNETES);
            props.setKeyAlias("rsa-k8s");
            props.getKubernetes().setRole("crypto-server");
            props.getKubernetes().setJwt("mock-k8s-service-account-jwt-token");
            props.setSecretPath("secret/data/crypto/k8s-keys");

            // 1. Authenticate to Vault via Kubernetes Auth & synchronize keys
            VaultKeySynchronizer synchronizer = new VaultKeySynchronizer(props);
            KeyRing keyRing = synchronizer.syncToKeyRing();
            CryptoServer server = new CryptoServer(keyRing);

            // 2. Client fetches public key
            PublicKeyResponse pubKeyResponse = server.getPublicKey();
            assertEquals("rsa-k8s:1", pubKeyResponse.keyId());

            // 3. Client prepares encrypted request
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey sessionKey = keyGen.generateKey();
            byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());

            String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, server.publicKey());
            String encryptedData = AesGcmCipher.encryptAsBase64("K8s-Vault-Auth-Successful", sessionKey, iv);

            CipherRequestPayload payload = new CipherRequestPayload(
                    pubKeyResponse.keyId(),
                    encryptedSessionKey,
                    EncodingUtils.toBase64(iv),
                    encryptedData
            );

            // 4. Server performs local decryption in memory
            String decrypted = server.decrypt(payload);
            assertEquals("K8s-Vault-Auth-Successful", decrypted);
        } finally {
            mockVault.stop(0);
        }
    }
}
