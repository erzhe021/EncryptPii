package com.ikea.crypto.stc.key.rotation;

import com.ikea.crypto.stc.config.VaultProperties;
import com.ikea.crypto.stc.model.KeyMetadata;
import com.ikea.crypto.stc.key.KeyRing;
import com.ikea.crypto.stc.vault.*;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Optional;

/**
 * Coordinates multi-pod RSA key rotation using Double-Checked Refresh and Vault KV v2 Check-And-Set (CAS).
 * Guarantees that only ONE pod performs rotation in production, while other pods synchronize the latest version.
 */
@Slf4j
public class VaultRotationCoordinator {

    private final VaultKeyRepository repository;
    private final VaultProperties properties;
    private final VaultKeyCodec codec;

    public VaultRotationCoordinator(VaultKeyRepository repository, VaultProperties properties, VaultKeyCodec codec) {
        this.repository = repository;
        this.properties = properties;
        this.codec = codec;
    }

    /**
     * Executes distributed key rotation for the specified key alias.
     *
     * @param keyRing        in-memory key ring to query and update
     * @param targetKeyAlias target key alias to rotate
     * @param force          if true, bypasses double-checked refresh
     * @return the active KeyEntry (either freshly rotated or synchronized from another winning pod)
     */
    public KeyRing.KeyEntry rotate(KeyRing keyRing, String targetKeyAlias, boolean force)
            throws GeneralSecurityException, IOException, InterruptedException {
        long now = System.currentTimeMillis();
        String alias = (targetKeyAlias != null && !targetKeyAlias.isBlank()) ? targetKeyAlias.trim() : properties.getKeyAlias();

        // 1. 双重检查（Double-Checked Refresh）
        Optional<VaultClient.VaultSecretEntry> latestOpt = repository.readSecretVersionRaw(alias, null);
        long currentLocalVersion = keyRing.getCurrentVersion(alias);
        KeyRing.KeyEntry currentLocalEntry = (keyRing.getActiveKeyEntry() != null && alias.equals(keyRing.getActiveKeyEntry().metadata().keyAlias()))
                ? keyRing.getActiveKeyEntry() : keyRing.findActiveKeyEntry(alias).orElse(null);
        boolean localExpired = (currentLocalEntry == null || currentLocalEntry.metadata().isExpired(now));

        if (!force && latestOpt.isPresent()) {
            VaultClient.VaultSecretEntry latestSecret = latestOpt.get();
            int vaultVersion = latestSecret.version();
            KeyRing.KeyEntry vaultEntry = codec.deserializeKeyEntry(
                    latestSecret.data(),
                    vaultVersion,
                    latestSecret.createdTime(),
                    alias,
                    properties.getValidityMillis()
            );

            boolean vaultKeyValid = !vaultEntry.metadata().isExpired(now);
            boolean vaultIsNewer = vaultVersion > currentLocalVersion;

            // 若 Vault 中已有未过期的更新版本，直接同步至本地内存，轮换终止
            if (vaultKeyValid && (vaultIsNewer || localExpired)) {
                log.info("Double-checked refresh: Vault already contains valid unexpired key (version={}). Syncing to local memory and terminating rotation.", vaultVersion);
                keyRing.registerKeyEntry(vaultEntry, true);
                return vaultEntry;
            }
        }

        // 2. 分布式锁抢占（Vault KV2 CAS）
        int expectedCas = latestOpt.map(VaultClient.VaultSecretEntry::version).orElse(0);
        return executeCasWrite(keyRing, alias, expectedCas, now);
    }

    /**
     * Bootstraps the initial key in Vault with CAS=0, avoiding a redundant double-check query
     * when Vault is already known to be empty (avoiding duplicate 404s).
     */
    public void bootstrapInitialKey(KeyRing keyRing, String targetKeyAlias)
            throws GeneralSecurityException, IOException, InterruptedException {
        String alias = (targetKeyAlias != null && !targetKeyAlias.isBlank()) ? targetKeyAlias.trim() : properties.getKeyAlias();
        executeCasWrite(keyRing, alias, 0, System.currentTimeMillis());
    }

    private KeyRing.KeyEntry executeCasWrite(KeyRing keyRing, String alias, int expectedCas, long now)
            throws GeneralSecurityException, IOException, InterruptedException {
        KeyPair keyPair = keyRing.generateKeyPair();

        try {
            VaultClient.VaultWriteResult writeResult = repository.writeKeyWithCas(alias, keyPair, expectedCas);
            // 获锁 Pod：执行密钥生成、写入 Vault、更新本地
            long latestVersion = writeResult.version();
            long createdAt = codec.parseCreatedTime(writeResult.createdTime(), now);
            long expiresAt = createdAt + properties.getValidityMillis();
            String newKeyId = KeyMetadata.buildKeyId(alias, latestVersion);
            KeyMetadata metadata = new KeyMetadata(newKeyId, createdAt, expiresAt);
            KeyRing.KeyEntry newEntry = new KeyRing.KeyEntry(metadata, keyPair);

            keyRing.registerKeyEntry(newEntry, true);
            keyRing.purgeExpiredKeys(now);
            log.info("CAS won: successfully rotated key for alias '{}' to version {}", alias, latestVersion);
            return newEntry;
        } catch (VaultCasMismatchException e) {
            // 未获锁 Pod：等待 1~2 秒后重新从 Vault 读取最新版本
            log.info("CAS conflict detected (expected cas={}): another pod won rotation. Waiting {}ms and fetching latest from Vault.",
                    expectedCas, properties.getCasBackoffMillis());
            return backoffAndFetchLatest(keyRing, alias, expectedCas);
        }
    }

    /**
     * Backs off for a configurable duration (default 1~2s) and fetches the newly rotated key from Vault.
     */
    private KeyRing.KeyEntry backoffAndFetchLatest(KeyRing keyRing, String alias, int previousVersion)
            throws IOException, InterruptedException, GeneralSecurityException {
        long waitTime = properties.getCasBackoffMillis();
        if (waitTime > 0) {
            log.info("Backing off for {} ms before fetching latest key from Vault...", waitTime);
            Thread.sleep(waitTime);
        }

        int maxRetries = Math.max(1, properties.getCasMaxRetries());
        long retryInterval = Math.max(50L, properties.getCasRetryIntervalMillis());

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            Optional<VaultClient.VaultSecretEntry> latestOpt = repository.readSecretVersionRaw(alias, null);
            if (latestOpt.isPresent()) {
                VaultClient.VaultSecretEntry latestSecret = latestOpt.get();
                if (latestSecret.version() > previousVersion) {
                    KeyRing.KeyEntry entry = codec.deserializeKeyEntry(
                            latestSecret.data(),
                            latestSecret.version(),
                            latestSecret.createdTime(),
                            alias,
                            properties.getValidityMillis()
                    );
                    keyRing.registerKeyEntry(entry, true);
                    log.info("Successfully fetched and activated latest key version {} from Vault after CAS contention", latestSecret.version());
                    return entry;
                }
            }
            if (attempt < maxRetries) {
                Thread.sleep(retryInterval);
            }
        }

        throw new IllegalStateException("Failed to fetch new key version from Vault after CAS contention for alias: " + alias
                + ", previousVersion was " + previousVersion);
    }
}
