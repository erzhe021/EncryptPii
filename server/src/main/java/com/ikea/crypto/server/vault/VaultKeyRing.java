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
        super(properties.getKeyAlias(), properties.getValidityMillis(), properties.getGracePeriodMillis());
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
            loadKeysFromVault(vaultToken);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while initializing VaultKeyRing", e);
        }
    }

    private void loadKeysFromVault(String vaultToken) throws GeneralSecurityException, IOException, InterruptedException {
        Optional<VaultClient.VaultSecretEntry> latestOpt = vaultClient.readSecretVersion(vaultToken, properties.getSecretPath(), null);

        if (latestOpt.isEmpty()) {
            if (properties.isAutoBootstrap()) {
                log.info("No RSA keys found in Vault at path '{}'. Auto-generating initial key pair...", properties.getSecretPath());
                rotateKey();
                return;
            } else {
                throw new IllegalStateException("No RSA keys found in Vault at path: " + properties.getSecretPath());
            }
        }

        VaultClient.VaultSecretEntry latestSecret = latestOpt.get();
        JsonNode latestData = latestSecret.data();

        // Vault KV 原生多版本模式：单 key 对象，按版本回溯加载过渡期密钥
        KeyFactory keyFactory = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA);
        int currentVersion = latestSecret.version();
        KeyEntry activeEntry = parseKeyEntryFromVersion(latestData, currentVersion, latestSecret.createdTime(), keyFactory);
        registerKeyEntry(activeEntry, true);
        log.info("Loaded active key from Vault KV v2: keyId={}, version={}",
                activeEntry.metadata().keyId(), currentVersion);

        // 自动向前回溯历史版本（version: currentVersion - 1 down to 1）
        for (int v = currentVersion - 1; v >= 1; v--) {
            try {
                Optional<VaultClient.VaultSecretEntry> historicalOpt = vaultClient.readSecretVersion(vaultToken, properties.getSecretPath(), v);
                if (historicalOpt.isEmpty()) {
                    continue;
                }
                VaultClient.VaultSecretEntry historicalSecret = historicalOpt.get();
                KeyEntry historicalEntry = parseKeyEntryFromVersion(historicalSecret.data(), v, historicalSecret.createdTime(), keyFactory);

                // 核心过滤：若已超出过渡期，立即停止回溯（更早的版本必然更早过期）
                if (isExpiredBeyondGrace(historicalEntry.metadata())) {
                    log.info("Historical key '{}' (version {}) has expired beyond grace period. Stopping backwards scan.",
                            historicalEntry.metadata().keyId(), v);
                    break;
                }

                registerKeyEntry(historicalEntry, false);
                log.info("Loaded historical transition key from Vault: keyId={}, version={}",
                        historicalEntry.metadata().keyId(), v);
            } catch (Exception e) {
                log.warn("Failed to load historical key version {} from Vault: {}", v, e.getMessage());
            }
        }

        if (getActiveKeyEntry() == null || getActiveKeyEntry().metadata().isExpired()) {
            log.info("Active RSA key in Vault is absent or expired, rotating to a new key...");
            rotateKey();
        }

        purgeExpiredKeys();
    }

    /**
     * Rotates to a new RSA key pair, persisting the new key to Vault KV v2.
     * Vault KV v2 automatically assigns an incremented version number.
     */
    @Override
    public synchronized KeyEntry rotateKey() throws GeneralSecurityException, IOException {
        try {
            KeyEntry newEntry = super.rotateKey();
            saveKeyToVault(newEntry);
            return newEntry;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while rotating key in Vault", e);
        }
    }

    @Override
    public synchronized int purgeExpiredKeys(long now) {
        return super.purgeExpiredKeys(now);
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

    private void saveKeyToVault(KeyEntry entry) throws IOException, InterruptedException {
        String vaultToken = authenticate();
        Map<String, Object> payload = new HashMap<>();
        payload.put("publicKey", EncodingUtils.toBase64(entry.publicKey().getEncoded()));
        payload.put("privateKey", EncodingUtils.toBase64(entry.privateKey().getEncoded()));

        vaultClient.writeSecret(vaultToken, properties.getSecretPath(), payload);
        log.info("Saved key '{}' to Vault path '{}'", entry.metadata().keyId(), properties.getSecretPath());
    }

    private KeyEntry parseKeyEntryFromVersion(JsonNode node, int version, String createdTimeStr, KeyFactory keyFactory)
            throws GeneralSecurityException {
        long createdAt;
        if (createdTimeStr != null && !createdTimeStr.isBlank()) {
            try {
                createdAt = java.time.Instant.parse(createdTimeStr).toEpochMilli();
            } catch (Exception e) {
                createdAt = System.currentTimeMillis();
            }
        } else {
            createdAt = System.currentTimeMillis();
        }

        long expiresAt = createdAt + getValidityMillis();
        String keyId = KeyMetadata.buildKeyId(getKeyAlias(), version);

        String pubBase64 = node.path("publicKey").asText();
        String privBase64 = node.path("privateKey").asText();
        if (pubBase64.isBlank() || privBase64.isBlank()) {
            throw new IllegalArgumentException("publicKey and privateKey must not be empty in Vault secret version " + version);
        }

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
