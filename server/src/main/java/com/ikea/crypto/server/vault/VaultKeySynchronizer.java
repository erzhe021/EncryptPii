package com.ikea.crypto.server.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.model.payload.KeyMetadata;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.server.service.KeyRing;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Synchronizes cryptographic keys from HashiCorp Vault into an in-memory KeyRing.
 * Eliminates disk dependencies across pods while keeping RSA decryption local and fast.
 */
@Slf4j
@Component
public class VaultKeySynchronizer {

    private final VaultProperties properties;
    private final VaultClient vaultClient;

    @Autowired
    public VaultKeySynchronizer(VaultProperties properties) {
        this.properties = properties;
        this.vaultClient = new VaultClient(properties.getAddr());
    }

    public VaultKeySynchronizer(VaultProperties properties, VaultClient vaultClient) {
        this.properties = properties;
        this.vaultClient = vaultClient;
    }

    /**
     * Authenticates with Vault using the configured authentication method and retrieves a Vault token.
     */
    public String authenticate() throws IOException, InterruptedException {
        if (properties.getAuthMethod() == VaultProperties.AuthMethod.KUBERNETES) {
            String jwt = resolveKubernetesJwt();
            String role = properties.getKubernetes().getRole();
            log.info("Authenticating to Vault using Kubernetes auth method, role='{}'", role);
            return vaultClient.loginWithKubernetes(role, jwt);
        } else {
            log.info("Using configured Vault token for authentication");
            return properties.getToken();
        }
    }

    /**
     * Synchronizes RSA keys from Vault KV v2 into an in-memory KeyRing.
     *
     * @return Fully populated in-memory KeyRing
     */
    public KeyRing syncToKeyRing() throws GeneralSecurityException, IOException, InterruptedException {
        VaultKeyRing vaultKeyRing = new VaultKeyRing(properties, vaultClient);
        vaultKeyRing.initialize();
        return vaultKeyRing;
    }

    private KeyRing.KeyEntry parseKeyEntry(JsonNode node, KeyFactory keyFactory) throws GeneralSecurityException {
        String keyId = node.path("keyId").asText();
        String pubBase64 = node.path("publicKey").asText();
        String privBase64 = node.path("privateKey").asText();
        long createdAt = node.path("createdAt").asLong(System.currentTimeMillis());
        long expiresAt = node.path("expiresAt").asLong(createdAt + KeyRing.DEFAULT_VALIDITY_MILLIS);

        byte[] pubBytes = EncodingUtils.fromBase64(pubBase64);
        byte[] privBytes = EncodingUtils.fromBase64(privBytesBase64(privBase64));

        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        KeyMetadata metadata = new KeyMetadata(keyId, createdAt, expiresAt);
        return new KeyRing.KeyEntry(metadata, keyPair);
    }

    private String privBytesBase64(String priv) {
        return priv.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
    }

    private KeyRing.KeyEntry generateAndStoreNewKey(String vaultToken, String path)
            throws GeneralSecurityException, IOException, InterruptedException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        long now = System.currentTimeMillis();
        long expiresAt = now + KeyRing.DEFAULT_VALIDITY_MILLIS;
        String keyId = "rsa-vault-" + java.time.LocalDate.now().toString().replace("-", "");

        Map<String, Object> data = new HashMap<>();
        data.put("keyId", keyId);
        data.put("publicKey", EncodingUtils.toBase64(keyPair.getPublic().getEncoded()));
        data.put("privateKey", EncodingUtils.toBase64(keyPair.getPrivate().getEncoded()));
        data.put("createdAt", now);
        data.put("expiresAt", expiresAt);

        vaultClient.writeSecret(vaultToken, path, data);

        KeyMetadata metadata = new KeyMetadata(keyId, now, expiresAt);
        return new KeyRing.KeyEntry(metadata, keyPair);
    }

    private String resolveKubernetesJwt() throws IOException {
        // If explicit JWT is provided in properties, use it
        if (properties.getKubernetes().getJwt() != null && !properties.getKubernetes().getJwt().isBlank()) {
            return properties.getKubernetes().getJwt().trim();
        }

        // Otherwise read from mounted ServiceAccount token file
        Path tokenFile = Path.of(properties.getKubernetes().getTokenPath());
        if (Files.exists(tokenFile)) {
            return Files.readString(tokenFile).trim();
        }

        throw new IllegalStateException("Kubernetes ServiceAccount token file not found at " + tokenFile
                + ", and no explicit jwt was configured.");
    }
}
