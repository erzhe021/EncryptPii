package com.ikea.crypto.stc.key;

import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.SessionKeyService;
import com.ikea.crypto.stc.exception.*;
import com.ikea.crypto.stc.key.rotation.RotationLog;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.KeyMetadata;
import com.ikea.crypto.stc.model.PublicKeyResponse;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import com.ikea.crypto.stc.util.EncodingUtils;
import com.ikea.crypto.stc.vault.VaultKeyRing;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
public record CryptoServer(KeyRing keyRing) {

    /**
     * Backward-compatible constructor using a single static keypair with 1 year validity.
     */
    public CryptoServer(PrivateKey privateKey, PublicKey publicKey) {
        this(privateKey, publicKey, true, KeyRing.DEFAULT_GRACE_PERIOD_MILLIS + 1);
    }

    public CryptoServer(PrivateKey privateKey, PublicKey publicKey, boolean autoRotate) {
        this(privateKey, publicKey, autoRotate, KeyRing.DEFAULT_GRACE_PERIOD_MILLIS + 1);
    }

    public CryptoServer(
            PrivateKey privateKey,
            PublicKey publicKey,
            boolean autoRotate,
            long rotationBeforeExpiryMillis
    ) {
        this(createInMemoryKeyRing(privateKey, publicKey, autoRotate, rotationBeforeExpiryMillis));
    }

    private static KeyRing createInMemoryKeyRing(
            PrivateKey privateKey,
            PublicKey publicKey,
            boolean autoRotate,
            long rotationBeforeExpiryMillis
    ) {
        long validityMillis = KeyRing.DEFAULT_IN_MEMORY_KEY_VALIDITY_MILLIS;
        KeyRing ring = new KeyRing(
                "in-memory-test-key",
                validityMillis,
                KeyRing.DEFAULT_GRACE_PERIOD_MILLIS,
                autoRotate,
                rotationBeforeExpiryMillis
        );
        String keyAlias = "in-memory-test-key";
        String keyId = KeyMetadata.buildKeyId(keyAlias, 1);
        long now = System.currentTimeMillis();
        long expiresAt = now + validityMillis;
        KeyMetadata metadata = new KeyMetadata(keyId, now, expiresAt);
        KeyRing.KeyEntry entry = new KeyRing.KeyEntry(metadata, new KeyPair(publicKey, privateKey));

        ring.registerKeyEntry(entry, true);
        return ring;
    }

    public PublicKey publicKey() {
        return keyRing.getActiveKeyEntry().publicKey();
    }

    /**
     * Returns the active RSA public key for clients.
     */
    public PublicKeyResponse getPublicKey() {
        KeyRing.KeyEntry active = keyRing.getActiveKeyEntry();
        if (active == null) {
            log.error("No active key found in keyring");
            throw new KeyNotAvailableException("No active RSA key found in server keyring");
        }

        // Check if active key is absent or expired, rotate if needed
        if (keyRing.isRotationDue(active.metadata())) {
            if (!keyRing.isAutoRotate() && active.metadata().isExpired()) {
                throw new KeyNotAvailableException("Active RSA key has expired and automatic rotation is disabled");
            }
            if (keyRing.isAutoRotate()) {
                long triggerTime = System.currentTimeMillis();
                keyRing.logRotationDue(null, active.metadata(), triggerTime);
                active = rotateAutomatically(null, active.metadata(), triggerTime);
            }
        }

        return toPublicKeyResponse(active);
    }

    /**
     * Returns the active RSA public key for the specified keyAlias.
     */
    public PublicKeyResponse getPublicKey(String keyAlias) {
        if (keyAlias == null || keyAlias.isBlank()) {
            return getPublicKey();
        }
        KeyRing.KeyEntry entry = keyRing.findActiveKeyEntry(keyAlias)
                .orElseThrow(() -> new KeyNotAvailableException("No active RSA key found for keyAlias: " + keyAlias));
        if (keyRing.isRotationDue(entry.metadata())) {
            if (!keyRing.isAutoRotate() && entry.metadata().isExpired()) {
                throw new KeyNotAvailableException(
                        "Active RSA key has expired and automatic rotation is disabled for keyAlias: " + keyAlias
                );
            }
            if (keyRing.isAutoRotate()) {
                long triggerTime = System.currentTimeMillis();
                keyRing.logRotationDue(keyAlias, entry.metadata(), triggerTime);
                entry = rotateAutomatically(keyAlias, entry.metadata(), triggerTime);
            }
        }
        return toPublicKeyResponse(entry);
    }

    private PublicKeyResponse toPublicKeyResponse(KeyRing.KeyEntry entry) {
        return new PublicKeyResponse(
                EncodingUtils.toBase64(entry.publicKey().getEncoded()),
                entry.metadata().keyId(),
                entry.metadata().expiresAtEpochMillis(),
                keyRing.getRefreshAtEpochMillis(entry.metadata())
        );
    }

    private KeyRing.KeyEntry rotateAutomatically(String keyAlias, KeyMetadata triggerMetadata, long triggerTime) {
        long startNanos = System.nanoTime();
        try {
            KeyRing.KeyEntry result = keyRing.rotateIfDue(keyAlias);
            long completedTime = System.currentTimeMillis();
            Map<String, Object> event = rotationEvent("rsa_key_rotation_completed", keyAlias, triggerMetadata, triggerTime);
            event.put("activeKeyId", result.metadata().keyId());
            event.put("activeKeyCreatedAt", Instant.ofEpochMilli(result.metadata().createdAtEpochMillis()).toString());
            event.put("activeKeyExpiresAt", Instant.ofEpochMilli(result.metadata().expiresAtEpochMillis()).toString());
            event.put("completedAt", Instant.ofEpochMilli(completedTime).toString());
            event.put("durationMillis", (System.nanoTime() - startNanos) / 1_000_000);
            log.warn("Automatic RSA key rotation completed: {}", RotationLog.toJson(event));
            return result;
        } catch (GeneralSecurityException | IOException e) {
            logAutomaticRotationFailure(keyAlias, triggerMetadata, triggerTime, startNanos, e);
            throw new KeyNotAvailableException("Automatic RSA key rotation failed for keyAlias: " + keyAlias, e);
        } catch (RuntimeException e) {
            logAutomaticRotationFailure(keyAlias, triggerMetadata, triggerTime, startNanos, e);
            throw e;
        }
    }

    private void logAutomaticRotationFailure(
            String keyAlias,
            KeyMetadata triggerMetadata,
            long triggerTime,
            long startNanos,
            Throwable exception
    ) {
        long failedTime = System.currentTimeMillis();
        Map<String, Object> event = rotationEvent("rsa_key_rotation_failed", keyAlias, triggerMetadata, triggerTime);
        event.put("failedAt", Instant.ofEpochMilli(failedTime).toString());
        event.put("durationMillis", (System.nanoTime() - startNanos) / 1_000_000);
        log.error("Automatic RSA key rotation failed: {}", RotationLog.toJson(event), exception);
    }

    private Map<String, Object> rotationEvent(
            String eventName,
            String keyAlias,
            KeyMetadata triggerMetadata,
            long triggerTime
    ) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("event", eventName);
        event.put("alias", (keyAlias != null && !keyAlias.isBlank()) ? keyAlias.trim() : keyRing.getKeyAlias());
        event.put("previousKeyId", triggerMetadata.keyId());
        event.put("triggeredAt", Instant.ofEpochMilli(triggerTime).toString());
        event.put("previousKeyCreatedAt", Instant.ofEpochMilli(triggerMetadata.createdAtEpochMillis()).toString());
        event.put("previousKeyExpiresAt", Instant.ofEpochMilli(triggerMetadata.expiresAtEpochMillis()).toString());
        event.put("remainingValidityMillis", triggerMetadata.expiresAtEpochMillis() - triggerTime);
        return event;
    }

    /**
     * Rotates to a new RSA key version for the default key alias.
     */
    public PublicKeyResponse rotateKey() {
        return rotateKey(null);
    }

    /**
     * Rotates to a new RSA key version for the specified key alias.
     * Generates a new key pair with incremented version and makes it the active key.
     */
    public PublicKeyResponse rotateKey(String keyAlias) {
        try {
            KeyRing.KeyEntry newEntry = keyRing.rotateKey(keyAlias);
            return toPublicKeyResponse(newEntry);
        } catch (GeneralSecurityException | IOException e) {
            log.error("Failed to rotate RSA key for keyAlias: {}", keyAlias, e);
            throw new KeyNotAvailableException("Failed to rotate RSA key for keyAlias: " + keyAlias, e);
        }
    }

    /**
     * Forces rotation to a new RSA key version for the specified key alias, bypassing double-checked refresh.
     */
    public PublicKeyResponse forceRotateKey(String keyAlias) {
        try {
            KeyRing.KeyEntry newEntry;
            if (keyRing instanceof VaultKeyRing vaultKeyRing) {
                newEntry = vaultKeyRing.forceRotateKey(keyAlias);
            } else {
                newEntry = keyRing.rotateKey(keyAlias);
            }
            return toPublicKeyResponse(newEntry);
        } catch (GeneralSecurityException | IOException e) {
            log.error("Failed to force rotate RSA key for keyAlias: {}", keyAlias, e);
            throw new KeyNotAvailableException("Failed to force rotate RSA key for keyAlias: " + keyAlias, e);
        }
    }

    /**
     * Decrypts the request payload. Tries the specified keyId first, then falls back to other known keys
     * during the rotation transition period.
     */
    public String decrypt(CipherRequestPayload payload) throws GeneralSecurityException {
        validatePayload(payload);
        SecretKey sessionKey = decryptSessionKeyToSecretKey(payload.keyId(), payload.encryptedSessionKeyBase64());
        // Store the resolved session key in the request-scoped context for potential reuse
        CryptoSessionContextAccessor.setResolvedSessionKey(sessionKey);
        return decryptWithAes(payload, sessionKey);
    }

    public byte[] decryptSessionKey(String keyId, String encryptedSessionKeyBase64) throws GeneralSecurityException {
        return decryptSessionKeyToSecretKey(keyId, encryptedSessionKeyBase64).getEncoded();
    }

    /**
     * Decrypts the encrypted session key using the private key corresponding to keyId,
     * or attempts all available keys in the transition grace period if keyId is not matched/provided.
     */
    public SecretKey decryptSessionKeyToSecretKey(String keyId, String encryptedSessionKeyBase64) throws GeneralSecurityException {
        log.debug("start to decrypt session key, keyId={}, from encryptedSessionKeyBase64", keyId);
        if (!StringUtils.hasLength(encryptedSessionKeyBase64)) {
            throw new InvalidCryptoPayloadException("Encrypted session key is required but was not provided.");
        }
        String requestedAlias = null;
        if (keyId != null && !keyId.isBlank()) {
            requestedAlias = new KeyMetadata(keyId, 0, 0).keyAlias();
            if (!StringUtils.hasText(requestedAlias)
                    || keyRing.findActiveKeyEntry(requestedAlias).isEmpty()) {
                throw new InvalidKeyException();
            }
        }

        // 1. If keyId is provided, try that specific key first
        Optional<KeyRing.KeyEntry> requestedEntry = Optional.empty();
        if (keyId != null && !keyId.isBlank()) {
            requestedEntry = keyRing.findKeyEntry(keyId);
            if (requestedEntry.isPresent()) {
                try {
                    return SessionKeyService.decryptSessionKeyBase64(
                            encryptedSessionKeyBase64, requestedEntry.get().privateKey());
                } catch (GeneralSecurityException e) {
                    log.warn("Failed to decrypt session key with matched keyId={}, attempting keyring fallback", keyId, e);
                }
            }
        }

        // 2. Try the active key
        KeyRing.KeyEntry activeEntry = keyRing.getActiveKeyEntry();
        if (activeEntry != null && (requestedAlias == null
                || requestedAlias.equals(activeEntry.metadata().keyAlias()))) {
            try {
                return SessionKeyService.decryptSessionKeyBase64(encryptedSessionKeyBase64, activeEntry.privateKey());
            } catch (GeneralSecurityException e) {
                log.warn("Decryption with active key failed, trying historical transition keys in keyring...", e);
            }
        }

        // 3. Fallback across all available keys (grace period support for old clients during rotation)
        for (KeyRing.KeyEntry entry : keyRing.getAllKeyEntries()) {
            if (requestedAlias != null && !requestedAlias.equals(entry.metadata().keyAlias())) {
                continue;
            }
            if (activeEntry != null && entry.metadata().keyId().equals(activeEntry.metadata().keyId())) {
                continue;
            }
            try {
                SecretKey decrypted = SessionKeyService.decryptSessionKeyBase64(encryptedSessionKeyBase64, entry.privateKey());
                log.info("Successfully decrypted session key using historical transition key: {}", entry.metadata().keyId());
                return decrypted;
            } catch (GeneralSecurityException e) {
                log.warn("Fallback decryption failed for keyId={}", entry.metadata().keyId(), e);
            }
        }

        // 4. Fallback on-demand sync from Vault (in case another pod rotated without notifying this pod)
        if (keyRing instanceof VaultKeyRing vaultKeyRing) {
            try {
                KeyRing.KeyEntry latestEntry = vaultKeyRing.syncLatestKeyFromVault(requestedAlias);
                if (latestEntry != null && (activeEntry == null || !latestEntry.metadata().keyId().equals(activeEntry.metadata().keyId()))) {
                    try {
                        SecretKey decrypted = SessionKeyService.decryptSessionKeyBase64(encryptedSessionKeyBase64, latestEntry.privateKey());
                        log.info("Successfully decrypted session key after on-demand Vault sync of latest key: {}", latestEntry.metadata().keyId());
                        return decrypted;
                    } catch (GeneralSecurityException ignored) {
                    }
                }
            } catch (Exception e) {
                log.warn("Failed on-demand sync from Vault during decryption fallback: {}", e.getMessage());
            }
        }

        if (requestedAlias != null) {
            KeyMetadata requestedMetadata = new KeyMetadata(keyId, 0, 0);
            KeyRing.KeyEntry currentEntry = keyRing.findActiveKeyEntry(requestedMetadata.keyAlias()).orElse(null);
            if (currentEntry == null) {
                throw new InvalidKeyException();
            }
            KeyMetadata activeMetadata = currentEntry.metadata();
            Long requestedVersion = requestedMetadata.version();
            Long activeVersion = activeMetadata.version();
            if (requestedEntry.isEmpty()
                    && (requestedVersion == null || activeVersion == null || !requestedVersion.equals(activeVersion))) {
                throw new KeyExpiredException(getPublicKey(activeMetadata.keyAlias()));
            }
        }

        log.warn("Failed to decrypt session key with keyId={}, all known keys exhausted", keyId);
        throw new SessionKeyDecryptionException("Failed to decrypt session key: keyId may be expired, unknown, or ciphertext invalid.");
    }

    public void validatePayload(CipherRequestPayload payload) {
        if (payload == null) {
            throw new InvalidCryptoPayloadException("Encrypted request payload cannot be null.");
        }
        if (!StringUtils.hasLength(payload.encryptedSessionKeyBase64())) {
            throw new InvalidCryptoPayloadException("Encrypted session key is required but was not provided.");
        }
        if (!StringUtils.hasLength(payload.ivBase64())) {
            throw new InvalidCryptoPayloadException("IV is required but was not provided.");
        }
        if (!StringUtils.hasLength(payload.encryptedDataBase64())) {
            throw new InvalidCryptoPayloadException("Encrypted data is required but was not provided.");
        }
    }

    private String decryptWithAes(CipherRequestPayload payload, SecretKey sessionKey) throws GeneralSecurityException {
        try {
            return AesGcmCipher.decryptFromBase64(
                    payload.encryptedDataBase64(),
                    sessionKey,
                    payload.ivBase64()
            );
        } catch (BadPaddingException e) {
            log.warn("GCM authentication tag verification failed, ciphertext may have been tampered with or corrupted");
            throw new DataTamperedException("Encrypted data authentication failed: data corrupted or tampered with.", e);
        } catch (IllegalArgumentException e) {
            throw new InvalidCryptoPayloadException("Invalid Base64 format in encrypted data or IV.", e);
        }
    }
}
