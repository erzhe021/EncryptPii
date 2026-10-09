package com.ikea.crypto.stc.key;

import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.key.rotation.RotationLog;
import com.ikea.crypto.stc.model.KeyMetadata;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.*;
import java.time.Instant;
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
    public static final long DEFAULT_GRACE_PERIOD_MILLIS = 20 * 1000; // 20 seconds grace
    public static final long DEFAULT_IN_MEMORY_KEY_VALIDITY_MILLIS = 365L * 24 * 60 * 60 * 1000;

    @Getter
    private final String keyAlias;
    @Getter
    private final long validityMillis;
    @Getter
    private final long gracePeriodMillis;
    @Getter
    private final boolean autoRotate;
    @Getter
    private final long rotationBeforeExpiryMillis;

    @Getter
    private volatile KeyEntry activeKeyEntry;
    // Key entries are stored in a thread-safe map keyed by keyId for quick lookup.
    private final Map<String, KeyEntry> keyEntriesById = new ConcurrentHashMap<>();
    private final Map<String, Long> retirementTimeByKeyId = new ConcurrentHashMap<>();

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
        this(keyAlias, validityMillis, gracePeriodMillis, true,
                defaultRotationWindowMillis(gracePeriodMillis));
    }

    public KeyRing(String keyAlias, long validityMillis, long gracePeriodMillis, boolean autoRotate) {
        this(keyAlias, validityMillis, gracePeriodMillis, autoRotate,
                defaultRotationWindowMillis(gracePeriodMillis));
    }

    public KeyRing(
            String keyAlias,
            long validityMillis,
            long gracePeriodMillis,
            boolean autoRotate,
            long rotationBeforeExpiryMillis
    ) {
        if (validityMillis <= 0) {
            throw new IllegalArgumentException("validityMillis must be greater than zero");
        }
        if (gracePeriodMillis < 0 || gracePeriodMillis >= rotationBeforeExpiryMillis) {
            throw new IllegalArgumentException(
                    "gracePeriodMillis must be non-negative and less than rotationBeforeExpiryMillis"
            );
        }
        if (rotationBeforeExpiryMillis >= validityMillis) {
            throw new IllegalArgumentException(
                    "rotationBeforeExpiryMillis must be less than validityMillis"
            );
        }
        this.keyAlias = (keyAlias != null && !keyAlias.isBlank()) ? keyAlias.trim() : DEFAULT_KEY_ALIAS;
        this.validityMillis = validityMillis;
        this.gracePeriodMillis = gracePeriodMillis;
        this.autoRotate = autoRotate;
        this.rotationBeforeExpiryMillis = rotationBeforeExpiryMillis;
    }

    private static long defaultRotationWindowMillis(long gracePeriodMillis) {
        if (gracePeriodMillis == Long.MAX_VALUE) {
            throw new IllegalArgumentException("No rotation window can be greater than the grace period");
        }
        return gracePeriodMillis + 1;
    }

    /**
     * Initializes the key ring. Generates an initial key if none exists and optionally replaces expired keys.
     * Obsolete keys beyond the grace period are automatically cleaned up.
     */
    public synchronized void initialize() throws GeneralSecurityException, IOException {
        if (activeKeyEntry == null) {
            rotateKey();
        } else if (autoRotate && isRotationDue(activeKeyEntry.metadata())) {
            logRotationDue(keyAlias, activeKeyEntry.metadata(), System.currentTimeMillis());
            rotateKey();
        }

        // Clean up any historical keys whose grace period has expired
        purgeExpiredKeys();
    }

    /**
     * Registers a key entry into the keyring in memory (e.g. from Vault or external KMS).
     */
    public synchronized void registerKeyEntry(KeyEntry entry, boolean makeActive) {
        registerKeyEntry(entry, makeActive, null);
    }

    public synchronized void registerKeyEntry(KeyEntry entry, boolean makeActive, Long retiredAtEpochMillis) {
        if (entry == null) {
            return;
        }
        KeyEntry previousActiveForAlias = findLatestKeyEntryForAlias(entry.metadata().keyAlias());
        keyEntriesById.put(entry.metadata().keyId(), entry);
        if (retiredAtEpochMillis != null) {
            retirementTimeByKeyId.put(entry.metadata().keyId(), addGracePeriod(retiredAtEpochMillis));
        }
        logCurrentEntries(keyEntriesById);
        boolean becomesActive = makeActive
                || activeKeyEntry == null
                || entry.metadata().expiresAtEpochMillis() > activeKeyEntry.metadata().expiresAtEpochMillis();
        if (becomesActive) {
            if (previousActiveForAlias != null
                    && !previousActiveForAlias.metadata().keyId().equals(entry.metadata().keyId())) {
                retirementTimeByKeyId.put(
                        previousActiveForAlias.metadata().keyId(),
                        addGracePeriod(entry.metadata().createdAtEpochMillis())
                );
            }
            this.activeKeyEntry = entry;
        }
    }

    private KeyEntry findLatestKeyEntryForAlias(String alias) {
        if (alias == null || alias.isBlank()) {
            return null;
        }
        String prefix = alias + ":";
        KeyEntry latest = null;
        long highestVersion = Long.MIN_VALUE;
        for (KeyEntry entry : keyEntriesById.values()) {
            if (!entry.metadata().keyId().startsWith(prefix)) {
                continue;
            }
            Long version = entry.metadata().version();
            long candidateVersion = version == null ? Long.MIN_VALUE : version;
            if (latest == null || candidateVersion > highestVersion) {
                latest = entry;
                highestVersion = candidateVersion;
            }
        }
        return latest;
    }

    private long addGracePeriod(long rotationTimeMillis) {
        try {
            return Math.addExact(rotationTimeMillis, gracePeriodMillis);
        } catch (ArithmeticException e) {
            return Long.MAX_VALUE;
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
     * Returns all available key entries (active + transition keys within their grace period).
     * Retired keys beyond the grace period are purged and excluded.
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
        registerKeyEntry(newEntry, true);

        log.info("Rotated to new active RSA key: keyId={}, expiresAt={}",
                metadata.keyId(), Instant.ofEpochMilli(metadata.expiresAtEpochMillis()));
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
     * Purges retired keys whose grace period has expired at current time:
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
            // Active keys are retained even after expiry so they remain available until replaced.
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
        retirementTimeByKeyId.remove(keyId);
        log.info("Purged expired key beyond grace period: keyId={}", keyId);
        logCurrentEntries(keyEntriesById);
    }

    public boolean isExpiredBeyondGrace(KeyMetadata metadata) {
        return isExpiredBeyondGrace(metadata, System.currentTimeMillis());
    }

    public boolean isExpiredBeyondGrace(KeyMetadata metadata, long now) {
        if (metadata == null) {
            return false;
        }
        long retirementTime = retirementTimeByKeyId.getOrDefault(
                metadata.keyId(),
                addGracePeriod(metadata.expiresAtEpochMillis())
        );
        return now >= retirementTime;
    }

    public boolean isWithinGracePeriod(KeyMetadata metadata) {
        return isWithinGracePeriod(metadata, System.currentTimeMillis());
    }

    public boolean isWithinGracePeriod(KeyMetadata metadata, long now) {
        if (metadata == null) {
            return false;
        }
        long retirementTime = retirementTimeByKeyId.getOrDefault(
                metadata.keyId(),
                addGracePeriod(metadata.expiresAtEpochMillis())
        );
        return metadata.isExpired(now) && now < retirementTime;
    }

    public boolean isRotationDue(KeyMetadata metadata) {
        return isRotationDue(metadata, System.currentTimeMillis());
    }

    public boolean isRotationDue(KeyMetadata metadata, long now) {
        if (metadata == null) {
            return false;
        }
        if (metadata.isExpired(now)) {
            return true;
        }
        return metadata.expiresAtEpochMillis() - now <= rotationBeforeExpiryMillis;
    }

    public long getEffectiveRotationWindowMillis() {
        return rotationBeforeExpiryMillis;
    }

    public long getRefreshAtEpochMillis(KeyMetadata metadata) {
        return autoRotate
                ? metadata.expiresAtEpochMillis() - rotationBeforeExpiryMillis
                : metadata.expiresAtEpochMillis();
    }

    public void logRotationDue(String targetKeyAlias, KeyMetadata metadata, long now) {
        long remainingMillis = metadata.expiresAtEpochMillis() - now;
        String reason = metadata.isExpired(now) ? "expired" : "within-rotation-window";
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("event", "rsa_key_rotation_triggered");
        event.put("alias", (targetKeyAlias != null && !targetKeyAlias.isBlank()) ? targetKeyAlias.trim() : keyAlias);
        event.put("keyId", metadata.keyId());
        event.put("reason", reason);
        event.put("now", Instant.ofEpochMilli(now).toString());
        event.put("keyCreatedAt", Instant.ofEpochMilli(metadata.createdAtEpochMillis()).toString());
        event.put("keyExpiresAt", Instant.ofEpochMilli(metadata.expiresAtEpochMillis()).toString());
        event.put("remainingValidityMillis", remainingMillis);
        event.put("configuredRotationBeforeExpiryMillis", rotationBeforeExpiryMillis);
        event.put("effectiveRotationWindowMillis", getEffectiveRotationWindowMillis());
        log.warn("RSA key rotation triggered: {}", RotationLog.toJson(event));
    }

    public synchronized KeyEntry rotateIfDue(String targetKeyAlias)
            throws GeneralSecurityException, IOException {
        String alias = (targetKeyAlias != null && !targetKeyAlias.isBlank()) ? targetKeyAlias.trim() : keyAlias;
        KeyEntry current = findActiveKeyEntry(alias)
                .orElseThrow(() -> new IllegalStateException("No active RSA key found for keyAlias: " + alias));
        if (autoRotate && isRotationDue(current.metadata())) {
            return rotateIfDueKey(alias);
        }
        return current;
    }

    protected KeyEntry rotateIfDueKey(String alias) throws GeneralSecurityException, IOException {
        return rotateKey(alias);
    }

    private void logCurrentEntries(Map<String, KeyEntry> keyEntriesById) {
        log.debug("Current key entries in keyring: {}", keyEntriesById.keySet());
    }
}
