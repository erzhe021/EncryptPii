package com.ikea.crypto.server.service;

import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.model.payload.KeyMetadata;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.*;
import java.text.SimpleDateFormat;
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

    public static final long DEFAULT_VALIDITY_MILLIS = 365L * 24 * 60 * 60 * 1000; // 1 year
    public static final long DEFAULT_GRACE_PERIOD_MILLIS = 30L * 24 * 60 * 60 * 1000; // 30 days grace

    @Getter
    private final long validityMillis;
    @Getter
    private final long gracePeriodMillis;

    @Getter
    private volatile KeyEntry activeKeyEntry;
    // Key entries are stored in a thread-safe map keyed by keyId for quick lookup.
    private final Map<String, KeyEntry> keyEntriesById = new ConcurrentHashMap<>();

    public KeyRing() {
        this(DEFAULT_VALIDITY_MILLIS, DEFAULT_GRACE_PERIOD_MILLIS);
    }

    public KeyRing(long validityMillis, long gracePeriodMillis) {
        this.validityMillis = validityMillis;
        this.gracePeriodMillis = gracePeriodMillis;
    }

    public static KeyRing createInMemory() {
        return new KeyRing();
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
     * Rotates to a new RSA key pair. The newly generated key becomes the active key.
     * Previous keys remain in the keyring for decrypting requests in transition.
     * Any historical keys that have expired beyond the grace period are purged.
     */
    public synchronized KeyEntry rotateKey() throws GeneralSecurityException, IOException {
        long now = System.currentTimeMillis();
        String dateSuffix = new SimpleDateFormat("yyyyMMdd").format(new Date(now));
        String baseKeyId = "rsa-" + dateSuffix;
        String newKeyId = baseKeyId;

        // If a key with this keyId already exists (e.g., rotated on same day), append sequence
        int seq = 1;
        while (keyEntriesById.containsKey(newKeyId)) {
            newKeyId = baseKeyId + "-" + seq++;
        }

        long expiresAt = now + validityMillis;
        KeyMetadata metadata = new KeyMetadata(newKeyId, now, expiresAt);

        KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        KeyEntry newEntry = new KeyEntry(metadata, keyPair);
        keyEntriesById.put(newKeyId, newEntry);
        this.activeKeyEntry = newEntry;

        log.info("Rotated to new active RSA key: keyId={}, expiresAt={}", newKeyId, new Date(expiresAt));

        // Purge historical keys whose grace period has expired
        purgeExpiredKeys(now);

        return newEntry;
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
}
