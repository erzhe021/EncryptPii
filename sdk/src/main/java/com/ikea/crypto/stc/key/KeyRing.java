package com.ikea.crypto.stc.key;

import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.model.KeyMetadata;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * KeyRing manages the active RSA key pair as well as historical key pairs
 * in memory for smooth rotation and graceful fallback during transition periods.
 */
@Slf4j
public class KeyRing {

    public record KeyEntry(KeyMetadata metadata, KeyPair keyPair) {
        public PrivateKey privateKey() {
            return keyPair.getPrivate();
        }

        public PublicKey publicKey() {
            return keyPair.getPublic();
        }
    }

    public static final String DEFAULT_KEY_ALIAS = KeyMetadata.DEFAULT_KEY_ALIAS;
    public static final long DEFAULT_VALIDITY_MILLIS = 60 * 1000; // 1 minute
    public static final long DEFAULT_GRACE_PERIOD_MILLIS = 30 * 1000; // 30 seconds grace

    @Getter
    private final String keyAlias;
    @Getter
    private final long validityMillis;
    @Getter
    private final long gracePeriodMillis;

    @Getter
    private volatile KeyEntry activeKeyEntry;
    // Key entries are stored in a thread-safe map keyed by keyId for quick lookup.
    private final Map<String, KeyEntry> keyEntriesById = new ConcurrentHashMap<>();

    public KeyRing() {
        this(DEFAULT_KEY_ALIAS, DEFAULT_VALIDITY_MILLIS, DEFAULT_GRACE_PERIOD_MILLIS);
    }

    public KeyRing(String keyAlias) {
        this(keyAlias, DEFAULT_VALIDITY_MILLIS, DEFAULT_GRACE_PERIOD_MILLIS);
    }

    public KeyRing(long validityMillis, long gracePeriodMillis) {
        this(DEFAULT_KEY_ALIAS, validityMillis, gracePeriodMillis);
    }

    public KeyRing(String keyAlias, long validityMillis, long gracePeriodMillis) {
        this.keyAlias = (keyAlias != null && !keyAlias.isBlank()) ? keyAlias.trim() : DEFAULT_KEY_ALIAS;
        this.validityMillis = validityMillis;
        this.gracePeriodMillis = gracePeriodMillis;
    }

    /**
     * Initializes the key ring. Generates a new active key in memory if none exists or if expired.
     * Obsolete keys beyond the grace period are automatically cleaned up.
     */
    public synchronized void initialize() throws GeneralSecurityException, IOException {
        // Check if active key is absent or expired, rotate if needed
        if (activeKeyEntry == null || activeKeyEntry.metadata().isExpired()) {
            rotateKey();
        }

        // Clean up any historical keys whose grace period has expired
        purgeExpiredKeys();
    }

    /**
     * Registers a key entry into the keyring in memory (e.g. from Vault or external KMS).
     */
    public synchronized void registerKeyEntry(KeyEntry entry, boolean makeActive) {
        if (entry == null) {
            return;
        }
        keyEntriesById.put(entry.metadata().keyId(), entry);
        logCurrentEntries(keyEntriesById);
        if (makeActive || activeKeyEntry == null || entry.metadata().expiresAtEpochMillis() > activeKeyEntry.metadata().expiresAtEpochMillis()) {
            this.activeKeyEntry = entry;
        }
    }

    /**
     * Finds a key entry by keyId. If keyId is null or blank, returns the active key entry.
     * If the specified key has expired beyond the grace period, it is purged and rejected (returns empty).
     */
    public Optional<KeyEntry> findKeyEntry(String keyId) {
        if (keyId == null || keyId.isBlank()) {
            return Optional.ofNullable(activeKeyEntry);
        }
        KeyEntry entry = keyEntriesById.get(keyId);
        if (entry == null) {
            return Optional.empty();
        }
        if (entry != activeKeyEntry && isExpiredBeyondGrace(entry.metadata())) {
            log.warn("Key '{}' has expired beyond grace period and is rejected.", keyId);
            purgeKey(keyId);
            return Optional.empty();
        }
        return Optional.of(entry);
    }

    /**
     * Returns all available key entries (active + transition keys within grace period).
     * Keys expired beyond the grace period are purged and excluded.
     */
    public Collection<KeyEntry> getAllKeyEntries() {
        purgeExpiredKeys();
        return Collections.unmodifiableCollection(keyEntriesById.values());
    }

    /**
     * Finds the active or latest valid key entry for a specific key alias.
     */
    public Optional<KeyEntry> findActiveKeyEntry(String keyAlias) {
        purgeExpiredKeys();
        if (keyAlias == null || keyAlias.isBlank()) {
            return Optional.ofNullable(activeKeyEntry);
        }
        String targetAlias = keyAlias.trim();
        if (activeKeyEntry != null && targetAlias.equals(activeKeyEntry.metadata().keyAlias())) {
            return Optional.of(activeKeyEntry);
        }
        String prefix = targetAlias + ":";
        KeyEntry latest = null;
        long maxVersion = -1;
        for (KeyEntry entry : keyEntriesById.values()) {
            String id = entry.metadata().keyId();
            if (id != null && id.startsWith(prefix)) {
                Long ver = entry.metadata().version();
                long v = (ver != null) ? ver : 0;
                if (v > maxVersion && !isExpiredBeyondGrace(entry.metadata())) {
                    maxVersion = v;
                    latest = entry;
                }
            }
        }
        return Optional.ofNullable(latest);
    }

    /**
     * Determines the next sequential version number for the given key alias
     * by scanning existing keys in the key ring.
     */
    public synchronized long getNextVersion(String keyAlias) {
        long maxVersion = 0;
        String targetName = (keyAlias != null && !keyAlias.isBlank()) ? keyAlias.trim() : this.keyAlias;
        String prefix = targetName + ":";
        for (String id : keyEntriesById.keySet()) {
            if (id != null && id.startsWith(prefix)) {
                String verStr = id.substring(prefix.length());
                try {
                    long ver = Long.parseLong(verStr);
                    if (ver > maxVersion) {
                        maxVersion = ver;
                    }
                } catch (NumberFormatException ignored) {
                    // ignore non-numeric version suffix
                }
            }
        }
        return maxVersion + 1;
    }

    /**
     * Determines the current highest known version number in memory for the given key alias.
     */
    public long getCurrentVersion(String keyAlias) {
        String targetName = (keyAlias != null && !keyAlias.isBlank()) ? keyAlias.trim() : this.keyAlias;
        long maxVersion = getMaxVersion(targetName);
        if (maxVersion > 0) {
            return maxVersion;
        }
        if (activeKeyEntry != null) {
            KeyMetadata metadata = activeKeyEntry.metadata();
            if (metadata != null && targetName.equals(metadata.keyAlias()) && metadata.version() != null) {
                return Objects.requireNonNull(metadata.version());
            }
        }
        return 0;
    }

    private long getMaxVersion(String targetName) {
        long maxVersion = 0;
        String prefix = targetName + ":";
        for (String id : keyEntriesById.keySet()) {
            if (id != null && id.startsWith(prefix)) {
                String verStr = id.substring(prefix.length());
                try {
                    long ver = Long.parseLong(verStr);
                    if (ver > maxVersion) {
                        maxVersion = ver;
                    }
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return maxVersion;
    }

    public KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        generator.initialize(CryptoConstants.RSA_KEY_SIZE_BITS);
        return generator.generateKeyPair();
    }

    protected synchronized KeyEntry activateNewKeyEntry(KeyMetadata metadata, KeyPair keyPair, long now) {
        KeyEntry newEntry = new KeyEntry(metadata, keyPair);
        keyEntriesById.put(metadata.keyId(), newEntry);
        this.activeKeyEntry = newEntry;

        log.info("Rotated to new active RSA key: keyId={}, expiresAt={}", metadata.keyId(), new Date(metadata.expiresAtEpochMillis()));
        logCurrentEntries(keyEntriesById);

        // Purge historical keys whose grace period has expired
        purgeExpiredKeys(now);

        return newEntry;
    }

    /**
     * Rotates to a new RSA key pair for the default key alias.
     */
    public synchronized KeyEntry rotateKey() throws GeneralSecurityException, IOException {
        return rotateKey(this.keyAlias);
    }

    /**
     * Rotates to a new RSA key pair for the specified key alias.
     * The newly generated key becomes the active key.
     * Previous keys remain in the keyring for decrypting requests in transition.
     * Any historical keys that have expired beyond the grace period are purged.
     */
    public synchronized KeyEntry rotateKey(String targetKeyAlias) throws GeneralSecurityException, IOException {
        long now = System.currentTimeMillis();
        String alias = (targetKeyAlias != null && !targetKeyAlias.isBlank()) ? targetKeyAlias.trim() : this.keyAlias;
        long nextVersion = getNextVersion(alias);
        String newKeyId = KeyMetadata.buildKeyId(alias, nextVersion);

        long expiresAt = now + validityMillis;
        KeyMetadata metadata = new KeyMetadata(newKeyId, now, expiresAt);
        KeyPair keyPair = generateKeyPair();

        return activateNewKeyEntry(metadata, keyPair, now);
    }

    /**
     * Purges expired keys whose grace period has expired at current time:
     * - Removes them from keyEntriesById (in-memory)
     * Active key is never purged.
     *
     * @return the number of keys purged
     */
    public synchronized int purgeExpiredKeys() {
        return purgeExpiredKeys(System.currentTimeMillis());
    }

    /**
     * Purges expired keys whose grace period has expired at the given timestamp.
     *
     * @param now timestamp in epoch millis to evaluate expiration against
     * @return the number of keys purged
     */
    public synchronized int purgeExpiredKeys(long now) {
        List<String> keysToPurge = new ArrayList<>();
        for (Map.Entry<String, KeyEntry> mapEntry : keyEntriesById.entrySet()) {
            KeyEntry entry = mapEntry.getValue();
            // Only purge keys that are not the active key and have expired beyond the grace period
            // however, we keep the active key even if it has expired, to allow for graceful transition.
            if (entry != activeKeyEntry && isExpiredBeyondGrace(entry.metadata(), now)) {
                keysToPurge.add(mapEntry.getKey());
            }
        }

        for (String keyId : keysToPurge) {
            purgeKey(keyId);
        }

        return keysToPurge.size();
    }

    private synchronized void purgeKey(String keyId) {
        keyEntriesById.remove(keyId);
        log.info("Purged expired key beyond grace period: keyId={}", keyId);
        logCurrentEntries(keyEntriesById);
    }

    public boolean isExpiredBeyondGrace(KeyMetadata metadata) {
        return isExpiredBeyondGrace(metadata, System.currentTimeMillis());
    }

    public boolean isExpiredBeyondGrace(KeyMetadata metadata, long now) {
        return metadata != null && metadata.isGracePeriodExpired(gracePeriodMillis, now);
    }

    public boolean isWithinGracePeriod(KeyMetadata metadata) {
        return isWithinGracePeriod(metadata, System.currentTimeMillis());
    }

    public boolean isWithinGracePeriod(KeyMetadata metadata, long now) {
        return metadata != null && metadata.isWithinGracePeriod(gracePeriodMillis, now);
    }

    private void logCurrentEntries(Map<String, KeyEntry> keyEntriesById) {
        log.debug("Current key entries in keyring: {}", keyEntriesById.keySet());
    }
}
