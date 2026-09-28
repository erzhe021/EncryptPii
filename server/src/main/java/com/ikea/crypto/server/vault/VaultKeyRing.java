package com.ikea.crypto.server.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.model.payload.KeyMetadata;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.server.service.KeyRing;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * VaultKeyRing manages RSA key generation, retrieval, rotation, and lifecycle
 * completely in HashiCorp Vault KV v2 without any local filesystem dependency.
 */
@Slf4j
public class VaultKeyRing extends KeyRing {

    private final VaultProperties properties;
    private final VaultClient vaultClient;

    public VaultKeyRing(VaultProperties properties, VaultClient vaultClient) {
        super(properties.getValidityMillis(), properties.getGracePeriodMillis());
        this.properties = properties;
        this.vaultClient = vaultClient;
    }

    /**
     * Initializes keys from Vault KV v2.
     * If no keys exist, automatically generates the initial key pair and writes to Vault.
     */
    @Override
    public synchronized void initialize() throws GeneralSecurityException, IOException {
        try {
            String vaultToken = authenticate();
            Optional<JsonNode> secretOpt = vaultClient.readSecret(vaultToken, properties.getSecretPath());

            if (secretOpt.isEmpty()) {
                if (properties.isAutoBootstrap()) {
                    log.info("No RSA keys found in Vault at path '{}'. Auto-generating initial key pair...", properties.getSecretPath());
                    rotateKey();
                    return;
                } else {
                    throw new IllegalStateException("No RSA keys found in Vault at path: " + properties.getSecretPath());
                }
            }

            JsonNode dataNode = secretOpt.get();
            loadKeysFromJson(dataNode);

            if (getActiveKeyEntry() == null || getActiveKeyEntry().metadata().isExpired()) {
                log.info("Active RSA key in Vault is absent or expired, rotating to a new key...");
                rotateKey();
            }

            purgeExpiredKeys();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while initializing VaultKeyRing", e);
        }
    }

    /**
     * Rotates to a new RSA key pair, persisting the new key and transition keys in Vault KV v2.
     * The active key is updated in memory and obsolete keys beyond grace period are purged.
     */
    @Override
    public synchronized KeyEntry rotateKey() throws GeneralSecurityException, IOException {
        try {
            long now = System.currentTimeMillis();
            String dateSuffix = new SimpleDateFormat("yyyyMMdd").format(new Date(now));
            String baseKeyId = "rsa-" + dateSuffix;
            String newKeyId = baseKeyId;

            int seq = 1;
            while (findKeyEntry(newKeyId).isPresent()) {
                newKeyId = baseKeyId + "-" + seq++;
            }

            long expiresAt = now + getValidityMillis();
            KeyMetadata metadata = new KeyMetadata(newKeyId, now, expiresAt);

            KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            KeyEntry newEntry = new KeyEntry(metadata, keyPair);
            registerKeyEntry(newEntry, true);

            // Persist the updated key ring (active + transition keys) to Vault
            saveKeysToVault(newKeyId);

            log.info("Rotated to new active RSA key in Vault: keyId={}, expiresAt={}", newKeyId, new Date(expiresAt));

            // Purge historical keys whose grace period has expired
            purgeExpiredKeys(now);

            return newEntry;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while rotating key in Vault", e);
        }
    }

    @Override
    public synchronized int purgeExpiredKeys(long now) {
        int purgedCount = super.purgeExpiredKeys(now);
        if (purgedCount > 0 && getActiveKeyEntry() != null) {
            try {
                saveKeysToVault(getActiveKeyEntry().metadata().keyId());
                log.info("Updated Vault after purging {} expired keys beyond grace period", purgedCount);
            } catch (Exception e) {
                log.warn("Failed to synchronize purged keys to Vault: {}", e.getMessage());
            }
        }
        return purgedCount;
    }

    public String authenticate() throws IOException, InterruptedException {
        if (properties.getAuthMethod() == VaultProperties.AuthMethod.KUBERNETES) {
            String jwt = resolveKubernetesJwt();
            String role = properties.getKubernetes().getRole();
            log.info("Authenticating to Vault via Kubernetes Auth (role: '{}')", role);
            return vaultClient.loginWithKubernetes(role, jwt);
        } else {
            return properties.getToken();
        }
    }

    private void saveKeysToVault(String activeKeyId) throws IOException, InterruptedException {
        String vaultToken = authenticate();
        Map<String, Object> payload = new HashMap<>();
        payload.put("activeKeyId", activeKeyId);

        List<Map<String, Object>> keyList = new ArrayList<>();
        for (KeyEntry entry : getAllKeyEntries()) {
            Map<String, Object> item = new HashMap<>();
            item.put("keyId", entry.metadata().keyId());
            item.put("publicKey", EncodingUtils.toBase64(entry.publicKey().getEncoded()));
            item.put("privateKey", EncodingUtils.toBase64(entry.privateKey().getEncoded()));
            item.put("createdAt", entry.metadata().createdAtEpochMillis());
            item.put("expiresAt", entry.metadata().expiresAtEpochMillis());
            item.put("active", entry.metadata().keyId().equals(activeKeyId));
            keyList.add(item);
        }
        payload.put("keys", keyList);

        vaultClient.writeSecret(vaultToken, properties.getSecretPath(), payload);
    }

    private void loadKeysFromJson(JsonNode dataNode) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA);

        if (dataNode.has("keys") && dataNode.path("keys").isArray()) {
            String activeKeyId = dataNode.path("activeKeyId").asText(null);
            for (JsonNode keyItem : dataNode.path("keys")) {
                KeyEntry entry = parseKeyEntry(keyItem, keyFactory);
                boolean isActive = (activeKeyId != null && activeKeyId.equals(entry.metadata().keyId()))
                        || keyItem.path("active").asBoolean(false);
                registerKeyEntry(entry, isActive);
            }
        } else {
            KeyEntry entry = parseKeyEntry(dataNode, keyFactory);
            registerKeyEntry(entry, true);
        }

        log.info("Loaded keys from Vault into memory KeyRing. Active keyId={}",
                getActiveKeyEntry() != null ? getActiveKeyEntry().metadata().keyId() : "none");
    }

    private KeyEntry parseKeyEntry(JsonNode node, KeyFactory keyFactory) throws GeneralSecurityException {
        String keyId = node.path("keyId").asText();
        String pubBase64 = node.path("publicKey").asText();
        String privBase64 = node.path("privateKey").asText();
        long createdAt = node.path("createdAt").asLong(System.currentTimeMillis());
        long expiresAt = node.path("expiresAt").asLong(createdAt + getValidityMillis());

        byte[] pubBytes = EncodingUtils.fromBase64(pubBase64);
        byte[] privBytes = EncodingUtils.fromBase64(cleanPrivKeyBase64(privBase64));

        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        KeyMetadata metadata = new KeyMetadata(keyId, createdAt, expiresAt);
        return new KeyEntry(metadata, keyPair);
    }

    private String cleanPrivKeyBase64(String priv) {
        return priv.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
    }

    private String resolveKubernetesJwt() throws IOException {
        if (properties.getKubernetes().getJwt() != null && !properties.getKubernetes().getJwt().isBlank()) {
            return properties.getKubernetes().getJwt().trim();
        }

        Path tokenFile = Path.of(properties.getKubernetes().getTokenPath());
        if (Files.exists(tokenFile)) {
            return Files.readString(tokenFile).trim();
        }

        throw new IllegalStateException("Kubernetes ServiceAccount token file not found at " + tokenFile
                + ", and no explicit jwt was configured.");
    }
}
