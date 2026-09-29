package com.ikea.crypto.server.vault;

import com.ikea.crypto.server.service.KeyRing;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Optional;

/**
 * VaultKeyRing coordinates in-memory key storage with HashiCorp Vault KV v2.
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

    public VaultKeyRing(VaultProperties properties, VaultClient vaultClient) {
        super(properties.getKeyAlias(), properties.getValidityMillis(), properties.getGracePeriodMillis());
        this.properties = properties;
        this.vaultClient = vaultClient;
        this.authenticator = new VaultAuthenticator(properties, vaultClient);
        this.codec = new VaultKeyCodec();
        this.repository = new VaultKeyRepository(properties, vaultClient, this.authenticator, this.codec);
        this.rotationCoordinator = new VaultRotationCoordinator(this.repository, properties, this.codec);
    }

    public VaultKeyRing(
            VaultProperties properties,
            VaultClient vaultClient,
            VaultAuthenticator authenticator,
            VaultKeyCodec codec,
            VaultKeyRepository repository,
            VaultRotationCoordinator rotationCoordinator
    ) {
        super(properties.getKeyAlias(), properties.getValidityMillis(), properties.getGracePeriodMillis());
        this.properties = properties;
        this.vaultClient = vaultClient;
        this.authenticator = authenticator;
        this.codec = codec;
        this.repository = repository;
        this.rotationCoordinator = rotationCoordinator;
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
            if (properties.isAutoBootstrap()) {
                log.warn("No RSA keys found in Vault at path '{}'. Auto-generating initial key pair...", properties.getSecretPath());
                rotationCoordinator.bootstrapInitialKey(this, getKeyAlias());
                return;
            } else {
                throw new IllegalStateException("No RSA keys found in Vault at path: " + properties.getSecretPath());
            }
        }

        VaultClient.VaultSecretEntry latestSecret = latestOpt.get();
        int currentVersion = latestSecret.version();
        KeyEntry activeEntry = codec.deserializeKeyEntry(
                latestSecret.data(),
                currentVersion,
                latestSecret.createdTime(),
                getKeyAlias(),
                getValidityMillis()
        );

        // Stop backtracking if active key itself has expired beyond grace period
        if (isExpiredBeyondGrace(activeEntry.metadata())) {
            log.info("Active key '{}' (version {}) has expired beyond grace period. Auto-rotating...",
                    activeEntry.metadata().keyId(), currentVersion);
            rotateKey();
            return;
        }

        registerKeyEntry(activeEntry, true);
        log.info("Loaded active key from Vault KV v2: keyId={}, version={}", activeEntry.metadata().keyId(), currentVersion);

        // Backtrack historical versions within grace period
        for (int v = currentVersion - 1; v >= 1; v--) {
            try {
                Optional<VaultClient.VaultSecretEntry> historicalOpt = repository.readSecretVersionRaw(getKeyAlias(), v);
                if (historicalOpt.isEmpty()) {
                    continue;
                }
                VaultClient.VaultSecretEntry historicalSecret = historicalOpt.get();
                KeyEntry historicalEntry = codec.deserializeKeyEntry(
                        historicalSecret.data(),
                        v,
                        historicalSecret.createdTime(),
                        getKeyAlias(),
                        getValidityMillis()
                );

                if (isExpiredBeyondGrace(historicalEntry.metadata())) {
                    log.info("Historical key '{}' (version {}) has expired beyond grace period. Stopping backwards scan.",
                            historicalEntry.metadata().keyId(), v);
                    break;
                }

                registerKeyEntry(historicalEntry, false);
                log.info("Loaded historical key from Vault: keyId={}, version={}", historicalEntry.metadata().keyId(), v);
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

    private synchronized Optional<KeyEntry> fetchAndCacheFromVault(String keyId) {
        // Double check local memory under lock
        Optional<KeyEntry> localEntry = super.findKeyEntry(keyId);
        if (localEntry.isPresent()) {
            return localEntry;
        }

        String alias = keyId.substring(0, keyId.indexOf(':'));
        String versionStr = keyId.substring(keyId.indexOf(':') + 1);
        int version;
        try {
            version = Integer.parseInt(versionStr);
        } catch (NumberFormatException e) {
            log.warn("Invalid version in keyId '{}', cannot fetch from Vault", keyId);
            return Optional.empty();
        }

        try {
            log.info("Cache miss for keyId '{}' in local memory, performing on-demand fetch from Vault...", keyId);
            Optional<KeyEntry> remoteOpt = repository.readKeyVersion(alias, version);
            if (remoteOpt.isPresent()) {
                KeyEntry remoteEntry = remoteOpt.get();
                if (isExpiredBeyondGrace(remoteEntry.metadata())) {
                    log.warn("Key '{}' fetched from Vault has expired beyond grace period and is rejected.", keyId);
                    return Optional.empty();
                }

                // If remote key version is newer than local active key and is unexpired, promote to active
                boolean makeActive = (getActiveKeyEntry() == null
                        || (remoteEntry.metadata().version() != null
                            && getActiveKeyEntry().metadata().version() != null
                            && remoteEntry.metadata().version() > getActiveKeyEntry().metadata().version()
                            && !remoteEntry.metadata().isExpired()));

                registerKeyEntry(remoteEntry, makeActive);
                log.info("Successfully fetched and cached keyId '{}' on-demand from Vault (makeActive={})", keyId, makeActive);
                return Optional.of(remoteEntry);
            } else {
                log.warn("KeyId '{}' not found in Vault", keyId);
            }
        } catch (Exception e) {
            log.error("Failed to fetch keyId '{}' on-demand from Vault: {}", keyId, e.getMessage(), e);
        }

        return Optional.empty();
    }

    public synchronized KeyEntry rotateKey(String targetKeyAlias, boolean force) throws GeneralSecurityException, IOException {
        try {
            return rotationCoordinator.rotate(this, targetKeyAlias, force);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while rotating key in Vault", e);
        }
    }

    /**
     * Actively checks Vault for the latest key version. If Vault has a newer version than local memory,
     * updates local memory.
     */
    public synchronized KeyEntry syncLatestKeyFromVault(String targetKeyAlias) throws GeneralSecurityException, IOException {
        try {
            String alias = (targetKeyAlias != null && !targetKeyAlias.isBlank()) ? targetKeyAlias.trim() : getKeyAlias();
            Optional<KeyEntry> latestOpt = repository.readLatestKey(alias);
            if (latestOpt.isPresent()) {
                KeyEntry remoteEntry = latestOpt.get();
                long currentLocal = getCurrentVersion(alias);
                if (remoteEntry.metadata().version() != null && remoteEntry.metadata().version() > currentLocal) {
                    registerKeyEntry(remoteEntry, true);
                    log.info("Synced newer key version {} from Vault into local memory", remoteEntry.metadata().version());
                    return remoteEntry;
                }
            }
            return getActiveKeyEntry();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while syncing latest key from Vault", e);
        }
    }

    public synchronized KeyEntry syncLatestKeyFromVault() throws GeneralSecurityException, IOException {
        return syncLatestKeyFromVault(getKeyAlias());
    }

    public String authenticate() throws IOException, InterruptedException {
        return authenticator.authenticate();
    }

    public VaultClient.VaultWriteResult saveKeyPairToVault(String alias, KeyPair keyPair) throws IOException, InterruptedException {
        return repository.writeKeyWithCas(alias, keyPair, null);
    }

    public VaultClient.VaultWriteResult saveKeyPairToVault(String alias, KeyPair keyPair, Integer cas) throws IOException, InterruptedException {
        return repository.writeKeyWithCas(alias, keyPair, cas);
    }
}
