package com.ikea.crypto.server.service;

import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.model.payload.KeyMetadata;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * KeyRing manages the active RSA key pair as well as historical key pairs
 * for smooth rotation and graceful fallback during transition periods.
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

    private static final Pattern KEY_ID_PATTERN = Pattern.compile("^rsa-(\\d{8})$");
    public static final long DEFAULT_VALIDITY_MILLIS = 365L * 24 * 60 * 60 * 1000; // 1 year
    public static final long DEFAULT_GRACE_PERIOD_MILLIS = 30L * 24 * 60 * 60 * 1000; // 30 days grace

    private final Path keyDirectory;
    private final long validityMillis;
    private final long gracePeriodMillis;

    private volatile KeyEntry activeKeyEntry;
    private final Map<String, KeyEntry> keyEntriesById = new ConcurrentHashMap<>();

    public KeyRing(Path keyDirectory) {
        this(keyDirectory, DEFAULT_VALIDITY_MILLIS, DEFAULT_GRACE_PERIOD_MILLIS);
    }

    public KeyRing(Path keyDirectory, long validityMillis, long gracePeriodMillis) {
        this.keyDirectory = keyDirectory;
        this.validityMillis = validityMillis;
        this.gracePeriodMillis = gracePeriodMillis;
    }

    /**
     * Initializes the key ring by scanning existing keys and generating a new active key if none exists or if expired.
     */
    public synchronized void initialize() throws GeneralSecurityException, IOException {
        Files.createDirectories(keyDirectory);
        loadExistingKeys();

        // Check if active key is absent or expired, rotate if needed
        if (activeKeyEntry == null || activeKeyEntry.metadata().isExpired()) {
            rotateKey();
        }
    }

    public KeyEntry getActiveKeyEntry() {
        return activeKeyEntry;
    }

    /**
     * Finds a key entry by keyId. If keyId is null or blank, returns the active key entry.
     */
    public Optional<KeyEntry> findKeyEntry(String keyId) {
        if (keyId == null || keyId.isBlank()) {
            return Optional.ofNullable(activeKeyEntry);
        }
        return Optional.ofNullable(keyEntriesById.get(keyId));
    }

    /**
     * Returns all available key entries (active + transition/grace period keys).
     */
    public Collection<KeyEntry> getAllKeyEntries() {
        return Collections.unmodifiableCollection(keyEntriesById.values());
    }

    /**
     * Rotates to a new RSA key pair. The newly generated key becomes the active key.
     * Previous keys remain in the keyring for decrypting requests in transition.
     */
    public synchronized KeyEntry rotateKey() throws GeneralSecurityException, IOException {
        long now = System.currentTimeMillis();
        String dateSuffix = new SimpleDateFormat("yyyyMMdd").format(new Date(now));
        String newKeyId = "rsa-" + dateSuffix;

        // If a key with this keyId already exists (e.g., rotated on same day), append sequence
        if (keyEntriesById.containsKey(newKeyId)) {
            newKeyId = newKeyId + "-" + (System.currentTimeMillis() % 10000);
        }

        long expiresAt = now + validityMillis;
        KeyMetadata metadata = new KeyMetadata(newKeyId, now, expiresAt);

        KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        // Save keys to directory
        saveKeyPair(newKeyId, keyPair, metadata);

        KeyEntry newEntry = new KeyEntry(metadata, keyPair);
        keyEntriesById.put(newKeyId, newEntry);
        this.activeKeyEntry = newEntry;

        log.info("Rotated to new active RSA key: keyId={}, expiresAt={}", newKeyId, new Date(expiresAt));
        return newEntry;
    }

    private void loadExistingKeys() throws GeneralSecurityException, IOException {
        KeyFactory keyFactory = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA);

        // Scan directory for *.pkcs8 files
        try (Stream<Path> stream = Files.list(keyDirectory)) {
            List<Path> privKeyFiles = stream
                    .filter(p -> p.getFileName().toString().endsWith(".pkcs8"))
                    .toList();

            for (Path privPath : privKeyFiles) {
                String fileName = privPath.getFileName().toString();
                String keyId = fileName.substring(0, fileName.length() - ".pkcs8".length());
                Path pubPath = keyDirectory.resolve(keyId + ".x509");
                Path metaPath = keyDirectory.resolve(keyId + ".meta");

                if (Files.exists(pubPath)) {
                    PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(privPath)));
                    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(pubPath)));
                    KeyPair keyPair = new KeyPair(publicKey, privateKey);

                    KeyMetadata metadata = loadOrCreateMetadata(keyId, metaPath);
                    KeyEntry entry = new KeyEntry(metadata, keyPair);
                    keyEntriesById.put(keyId, entry);

                    // Pick latest non-expired as active, or newest by expiresAt
                    if (activeKeyEntry == null || metadata.expiresAtEpochMillis() > activeKeyEntry.metadata().expiresAtEpochMillis()) {
                        activeKeyEntry = entry;
                    }
                }
            }
        }

        // Backward compatibility: check if default rsa-private-key.pkcs8 exists without date
        Path legacyPriv = keyDirectory.resolve("rsa-private-key.pkcs8");
        Path legacyPub = keyDirectory.resolve("rsa-public-key.x509");
        if (Files.exists(legacyPriv) && Files.exists(legacyPub) && !keyEntriesById.containsKey("rsa-legacy")) {
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(legacyPriv)));
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(legacyPub)));
            String legacyKeyId = "rsa-20261001";
            KeyMetadata metadata = new KeyMetadata(legacyKeyId, System.currentTimeMillis(), System.currentTimeMillis() + validityMillis);
            KeyEntry entry = new KeyEntry(metadata, new KeyPair(publicKey, privateKey));
            keyEntriesById.put(legacyKeyId, entry);
            if (activeKeyEntry == null) {
                activeKeyEntry = entry;
            }
        }
    }

    private KeyMetadata loadOrCreateMetadata(String keyId, Path metaPath) throws IOException {
        if (Files.exists(metaPath)) {
            List<String> lines = Files.readAllLines(metaPath);
            if (!lines.isEmpty()) {
                String[] parts = lines.get(0).split(",");
                if (parts.length >= 2) {
                    long createdAt = Long.parseLong(parts[0].trim());
                    long expiresAt = Long.parseLong(parts[1].trim());
                    return new KeyMetadata(keyId, createdAt, expiresAt);
                }
            }
        }
        // Fallback: derive from file creation / now
        long now = System.currentTimeMillis();
        long expiresAt = now + validityMillis;
        KeyMetadata meta = new KeyMetadata(keyId, now, expiresAt);
        Files.writeString(metaPath, now + "," + expiresAt);
        return meta;
    }

    private void saveKeyPair(String keyId, KeyPair keyPair, KeyMetadata metadata) throws IOException {
        Path privPath = keyDirectory.resolve(keyId + ".pkcs8");
        Path pubPath = keyDirectory.resolve(keyId + ".x509");
        Path metaPath = keyDirectory.resolve(keyId + ".meta");

        Files.write(privPath, keyPair.getPrivate().getEncoded());
        Files.write(pubPath, keyPair.getPublic().getEncoded());
        Files.writeString(metaPath, metadata.createdAtEpochMillis() + "," + metadata.expiresAtEpochMillis());
    }
}
