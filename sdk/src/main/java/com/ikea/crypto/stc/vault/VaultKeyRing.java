package com.ikea.crypto.stc.vault;

import com.ikea.crypto.stc.config.KeyLifecycleProperties;
import com.ikea.crypto.stc.config.VaultProperties;
import com.ikea.crypto.stc.exception.CryptoServerSideException;
import com.ikea.crypto.stc.key.KeyRing;
import com.ikea.crypto.stc.key.rotation.VaultRotationCoordinator;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Optional;

/**
 * VaultKeyRing coordinates in-memory key storage for one configured alias with HashiCorp Vault KV v2.
 * Delegates authentication, serialization, repository I/O, and rotation coordination
 * to dedicated single-responsibility components.
 */
@Slf4j
public class VaultKeyRing extends KeyRing {

    @Getter
    private final VaultProperties properties;
    @Getter
    private final VaultClient vaultClient;
    @Getter
    private final VaultAuthenticator authenticator;
    @Getter
    private final VaultKeyCodec codec;
    @Getter
    private final VaultKeyRepository repository;
    @Getter
    private final VaultRotationCoordinator rotationCoordinator;

    public VaultKeyRing(
            VaultProperties properties,
            KeyLifecycleProperties lifecycleProperties,
            VaultClient vaultClient,
            boolean autoRotate
    ) {
        this(properties, lifecycleProperties, vaultClient, autoRotate,
                lifecycleProperties.getRotationBeforeExpiryMillis());
    }

    public VaultKeyRing(
            VaultProperties properties,
            KeyLifecycleProperties lifecycleProperties,
            VaultClient vaultClient,
            boolean autoRotate,
            long rotationBeforeExpiryMillis
    ) {
        super(properties.getKeyAlias(), lifecycleProperties.getValidityMillis(),
                lifecycleProperties.getGracePeriodMillis(),
                autoRotate, rotationBeforeExpiryMillis);
        this.properties = properties;
        this.vaultClient = vaultClient;
        this.authenticator = new VaultAuthenticator(properties, vaultClient);
        this.codec = new VaultKeyCodec();
        this.repository = new VaultKeyRepository(
                properties, lifecycleProperties, vaultClient, this.authenticator, this.codec);
        this.rotationCoordinator = new VaultRotationCoordinator(
                this.repository, properties, lifecycleProperties, this.codec);
    }

    /**
     * Initializes keys from Vault KV v2.
     * Backtracks active and transition keys within grace period, auto-bootstrapping if none exist.
     */
    @Override
    public synchronized void initialize() throws GeneralSecurityException, IOException {
        try {
            loadKeysFromVault();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while initializing VaultKeyRing", e);
        }
    }

    private void loadKeysFromVault() throws GeneralSecurityException, IOException, InterruptedException {
        Optional<VaultClient.VaultSecretEntry> latestOpt = repository.readSecretVersionRaw(getKeyAlias(), null);
        if (latestOpt.isEmpty()) {
            bootstrapInitialKey();
            return;
        }

        VaultClient.VaultSecretEntry latestSecret = latestOpt.get();
        KeyEntry activeEntry = deserializeKeyEntry(latestSecret, latestSecret.version());
        if (isExpiredBeyondGrace(activeEntry.metadata())) {
            handleExpiredActiveKey(activeEntry);
            return;
        }

        registerKeyEntry(activeEntry, true);
        log.info("Loaded active key from Vault KV v2: keyId={}, version={}",
                activeEntry.metadata().keyId(), latestSecret.version());
        loadHistoricalKeys(latestSecret.version(), activeEntry.metadata().createdAtEpochMillis());
        rotateLoadedKeyIfDue();
        purgeExpiredKeys();
    }

    private void bootstrapInitialKey() throws GeneralSecurityException, IOException, InterruptedException {
        if (!properties.isAutoBootstrap()) {
            throw new IllegalStateException("No RSA keys found in Vault at path: " + properties.getSecretPath());
        }
        log.warn("No RSA keys found in Vault at path '{}'. Auto-generating initial key pair...", properties.getSecretPath());
        rotationCoordinator.bootstrapInitialKey(this, getKeyAlias());
    }

    private KeyEntry deserializeKeyEntry(VaultClient.VaultSecretEntry secret, int version)
            throws GeneralSecurityException {
        return codec.deserializeKeyEntry(
                secret.data(), version, secret.createdTime(), getKeyAlias(), getValidityMillis());
    }

    private void handleExpiredActiveKey(KeyEntry activeEntry) throws GeneralSecurityException, IOException {
        if (isAutoRotate()) {
            logRotationDue(getKeyAlias(), activeEntry.metadata(), System.currentTimeMillis());
            rotateKey();
            return;
        }
        log.warn("Active RSA key is beyond its grace period and automatic rotation is disabled: keyId={}",
                activeEntry.metadata().keyId());
        registerKeyEntry(activeEntry, true);
    }

    private void loadHistoricalKeys(int currentVersion, long nextVersionRotationTime) {
        for (int v = currentVersion - 1; v >= 1; v--) {
            Optional<KeyEntry> historical = readHistoricalKey(v);
            if (historical.isPresent()) {
                KeyEntry historicalEntry = historical.get();
                if (isRetiredBeyondGrace(nextVersionRotationTime)) {
                    log.info("Historical key '{}' (version {}) has expired beyond grace period. Stopping backwards scan.",
                            historicalEntry.metadata().keyId(), v);
                    return;
                }
                registerKeyEntry(historicalEntry, false, nextVersionRotationTime);
                nextVersionRotationTime = historicalEntry.metadata().createdAtEpochMillis();
                log.info("Loaded historical key from Vault: keyId={}, version={}", historicalEntry.metadata().keyId(), v);
            }
        }
    }

    private Optional<KeyEntry> readHistoricalKey(int version) {
        try {
            Optional<VaultClient.VaultSecretEntry> secret = repository.readSecretVersionRaw(getKeyAlias(), version);
            if (secret.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(deserializeKeyEntry(secret.get(), version));
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            log.warn("Failed to load historical key version {} from Vault", version, e);
            return Optional.empty();
        }
    }

    private void rotateLoadedKeyIfDue() throws GeneralSecurityException, IOException {
        KeyEntry loadedActive = getActiveKeyEntry();
        if (!isAutoRotate() || (loadedActive != null && !isRotationDue(loadedActive.metadata()))) {
            return;
        }
        if (loadedActive == null) {
            log.warn("RSA key rotation triggered because no active key was loaded: alias={}", getKeyAlias());
        } else {
            logRotationDue(getKeyAlias(), loadedActive.metadata(), System.currentTimeMillis());
        }
        rotateKey();
    }

    @Override
    public synchronized KeyEntry rotateKey() throws GeneralSecurityException, IOException {
        return rotateKey(getKeyAlias(), false);
    }

    @Override
    public synchronized KeyEntry rotateKey(String targetKeyAlias) throws GeneralSecurityException, IOException {
        return rotateKey(targetKeyAlias, false);
    }

    public synchronized KeyEntry forceRotateKey(String targetKeyAlias) throws GeneralSecurityException, IOException {
        return rotateKey(targetKeyAlias, true);
    }

    /**
     * Finds a key entry by keyId.
     * 1. Fast Path: Checks local in-memory KeyRing.
     * 2. Cache Miss: If not found locally, performs on-demand fallback fetch from Vault
     *    and caches the key in memory. This ensures multi-pod production environments
     *    can decrypt newly rotated keys from other pods immediately with zero disruption.
     */
    @Override
    public Optional<KeyEntry> findKeyEntry(String keyId) {
        Optional<KeyEntry> localEntry = super.findKeyEntry(keyId);
        if (localEntry.isPresent()) {
            return localEntry;
        }

        if (keyId == null || keyId.isBlank() || !keyId.contains(":")) {
            return Optional.empty();
        }

        return fetchAndCacheFromVault(keyId);
    }

    private Optional<KeyEntry> fetchAndCacheFromVault(String keyId) {
        Optional<KeyEntry> localEntry = super.findKeyEntry(keyId);
        if (localEntry.isPresent()) {
            return localEntry;
        }

        int separator = keyId.indexOf(':');
        String alias = keyId.substring(0, separator);
        if (alias.isBlank() || !getKeyAlias().equals(alias)) {
            return Optional.empty();
        }
        Optional<Integer> version = parseVaultVersion(keyId.substring(separator + 1), keyId);
        return version.flatMap(value -> fetchAndCacheVersion(keyId, alias, value));
    }

    private Optional<Integer> parseVaultVersion(String versionStr, String keyId) {
        try {
            int version = Integer.parseInt(versionStr);
            return version > 0 && versionStr.equals(Integer.toString(version))
                    ? Optional.of(version) : Optional.empty();
        } catch (NumberFormatException e) {
            log.warn("Invalid version in keyId '{}', cannot fetch from Vault", keyId, e);
            return Optional.empty();
        }
    }

    private Optional<KeyEntry> fetchAndCacheVersion(String keyId, String alias, int version) {
        try {
            log.info("Cache miss for keyId '{}' in local memory, performing on-demand fetch from Vault...", keyId);
            Optional<KeyEntry> remoteOpt = repository.readKeyVersion(alias, version);
            if (remoteOpt.isEmpty()) {
                log.warn("KeyId '{}' not found in Vault", keyId);
                return Optional.empty();
            }
            Optional<KeyEntry> nextEntry = version == Integer.MAX_VALUE
                    ? Optional.empty() : repository.readKeyVersion(alias, version + 1);
            return cacheRemoteKey(keyId, remoteOpt.get(), nextEntry);
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            throw new CryptoServerSideException("Failed to fetch key from Vault: " + keyId, e);
        }
    }

    private synchronized Optional<KeyEntry> cacheRemoteKey(
            String keyId, KeyEntry remoteEntry, Optional<KeyEntry> nextEntry) {
        Optional<KeyEntry> localEntry = super.findKeyEntry(keyId);
        if (localEntry.isPresent()) {
            return localEntry;
        }
        long rotatedAt = nextEntry.map(entry -> entry.metadata().createdAtEpochMillis())
                .orElse(remoteEntry.metadata().expiresAtEpochMillis());
        if (isRetiredBeyondGrace(rotatedAt)) {
            log.warn("Key '{}' fetched from Vault has expired beyond grace period and is rejected.", keyId);
            return Optional.empty();
        }
        boolean makeActive = nextEntry.isEmpty() && shouldPromote(remoteEntry);
        Long retirementTime = nextEntry.isPresent() ? rotatedAt : null;
        registerKeyEntry(remoteEntry, makeActive, retirementTime);
        log.info("Successfully fetched and cached keyId '{}' on-demand from Vault (makeActive={})", keyId, makeActive);
        return Optional.of(remoteEntry);
    }

    private boolean shouldPromote(KeyEntry remoteEntry) {
        if (remoteEntry.metadata().isExpired()) {
            return false;
        }
        KeyEntry activeEntry = getActiveKeyEntry();
        if (activeEntry == null) {
            return true;
        }
        if (!remoteEntry.metadata().keyAlias().equals(activeEntry.metadata().keyAlias())) {
            return false;
        }
        Long remoteVersion = remoteEntry.metadata().version();
        Long activeVersion = activeEntry.metadata().version();
        return remoteVersion != null && activeVersion != null
                && remoteVersion > activeVersion;
    }

    private boolean isRetiredBeyondGrace(long rotatedAt) {
        long now = System.currentTimeMillis();
        return now >= rotatedAt && now - rotatedAt >= getGracePeriodMillis();
    }

    public synchronized KeyEntry rotateKey(String targetKeyAlias, boolean force) throws GeneralSecurityException, IOException {
        String alias = resolveKeyAlias(targetKeyAlias);
        try {
            return rotationCoordinator.rotate(this, alias, force);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while rotating key in Vault", e);
        } catch (GeneralSecurityException | IOException e) {
            log.error("Failed to rotate key in Vault for alias '{}'", targetKeyAlias, e);
            throw e;
        }
    }

    @Override
    protected synchronized KeyEntry rotateIfDueKey(String targetKeyAlias) throws GeneralSecurityException, IOException {
        try {
            return rotationCoordinator.rotate(this, targetKeyAlias, false, true);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while proactively rotating key in Vault", e);
        }
    }

    /**
     * Actively checks Vault for the latest key version. If Vault has a newer version than local memory,
     * updates local memory. Returns the latest local entry for the requested alias, or null if absent.
     */
    public synchronized KeyEntry syncLatestKeyFromVault(String targetKeyAlias) throws GeneralSecurityException, IOException {
        String alias = resolveKeyAlias(targetKeyAlias);
        Optional<KeyEntry> latestOpt = repository.readLatestKey(alias);
        if (latestOpt.isPresent()) {
            KeyEntry remoteEntry = latestOpt.get();
            long currentLocal = getCurrentVersion(alias);
            Long remoteVersion = remoteEntry.metadata().version();
            if (remoteVersion != null && remoteVersion > currentLocal) {
                registerKeyEntry(remoteEntry, true);
                log.info("Synced newer key version {} from Vault into local memory", remoteVersion);
                return remoteEntry;
            }
        }
        return findActiveKeyEntry(alias).orElse(null);
    }
}
