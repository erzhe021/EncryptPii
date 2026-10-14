package com.ikea.crypto.stc.key;

import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.SessionKeyService;
import com.ikea.crypto.stc.exception.*;
import com.ikea.crypto.stc.key.rotation.RotationLog;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.KeyMetadata;
import com.ikea.crypto.stc.model.PublicKeyResponse;
import com.ikea.crypto.stc.util.EncodingUtils;
import com.ikea.crypto.stc.vault.VaultKeyRing;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * CryptoServer provides cryptographic services for clients, including RSA public key retrieval,
 * AES session key decryption, and automatic RSA key rotation.
 * <p>
 * This class interacts with a KeyRing to manage RSA keys and perform cryptographic operations.
 * It handles key rotation, session key decryption, and validation of encrypted payloads.
 * </p>
 */
@Slf4j
public record CryptoServer(KeyRing keyRing) {

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
            log.info("Automatic RSA key rotation completed: {}", RotationLog.toJson(event));
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
     * Decrypts the request payload with an already resolved AES session key.
     */
    public String decrypt(CipherRequestPayload payload, SecretKey sessionKey) throws GeneralSecurityException {
        validatePayload(payload);
        return decryptWithAes(payload, sessionKey);
    }

    /**
     * Decrypts the encrypted session key using the private key corresponding to keyId,
     * or attempts all available keys in the transition grace period if keyId is not matched/provided.
     */
    public SecretKey decryptSessionKeyToSecretKey(String keyId, String encryptedSessionKeyBase64) throws GeneralSecurityException {
        log.debug("start to decrypt session key, keyId={}, from encryptedSessionKeyBase64", keyId);
        validateEncryptedSessionKey(encryptedSessionKeyBase64);
        String requestedAlias = resolveRequestedAlias(keyId);
        Optional<KeyRing.KeyEntry> requestedEntry = StringUtils.hasText(keyId)
                ? keyRing.findKeyEntry(keyId)
                : Optional.empty();
        KeyRing.KeyEntry activeEntry = keyRing.getActiveKeyEntry();
        return tryDecryptRequestedKey(encryptedSessionKeyBase64, requestedEntry)
                .or(() -> tryDecryptActiveKey(encryptedSessionKeyBase64, requestedAlias, activeEntry))
                .or(() -> tryDecryptHistoricalKeys(encryptedSessionKeyBase64, requestedAlias, activeEntry))
                .or(() -> decryptWithLatestVaultKey(encryptedSessionKeyBase64, requestedAlias, activeEntry))
                .orElseThrow(() -> sessionKeyDecryptionFailure(
                        keyId, requestedAlias, requestedEntry));
    }

    private void validateEncryptedSessionKey(String encryptedSessionKeyBase64) {
        if (!StringUtils.hasLength(encryptedSessionKeyBase64)) {
            throw new InvalidCryptoRequestException("Encrypted session key is required but was not provided.");
        }
    }

    private Optional<SecretKey> tryDecryptRequestedKey(
            String encryptedSessionKeyBase64,
            Optional<KeyRing.KeyEntry> requestedEntry
    ) {
        return requestedEntry.flatMap(entry ->
                tryDecryptSessionKey(encryptedSessionKeyBase64, entry, "matched key"));
    }

    private Optional<SecretKey> tryDecryptActiveKey(
            String encryptedSessionKeyBase64,
            String requestedAlias,
            KeyRing.KeyEntry activeEntry
    ) {
        if (activeEntry == null || !matchesAlias(requestedAlias, activeEntry)) {
            return Optional.empty();
        }
        return tryDecryptSessionKey(encryptedSessionKeyBase64, activeEntry, "active key");
    }

    private Optional<SecretKey> tryDecryptHistoricalKeys(
            String encryptedSessionKeyBase64,
            String requestedAlias,
            KeyRing.KeyEntry activeEntry
    ) {
        return keyRing.getAllKeyEntries().stream()
                .filter(entry -> matchesAlias(requestedAlias, entry))
                .filter(entry -> !isActiveKey(entry, activeEntry))
                .map(entry -> tryDecryptSessionKey(encryptedSessionKeyBase64, entry, "historical key"))
                .flatMap(Optional::stream)
                .findFirst();
    }

    private boolean matchesAlias(String requestedAlias, KeyRing.KeyEntry entry) {
        return requestedAlias == null || requestedAlias.equals(entry.metadata().keyAlias());
    }

    private String resolveRequestedAlias(String keyId) {
        if (!StringUtils.hasText(keyId)) {
            return null;
        }
        String requestedAlias = new KeyMetadata(keyId, 0, 0).keyAlias();
        if (!StringUtils.hasText(requestedAlias) || keyRing.findActiveKeyEntry(requestedAlias).isEmpty()) {
            throw new InvalidKeyException();
        }
        return requestedAlias;
    }

    private Optional<SecretKey> tryDecryptSessionKey(
            String encryptedSessionKeyBase64,
            KeyRing.KeyEntry entry,
            String keyDescription
    ) {
        try {
            SecretKey sessionKey = SessionKeyService.decryptSessionKeyBase64(
                    encryptedSessionKeyBase64, entry.privateKey());
            log.info("Successfully decrypted session key using {}: {}", keyDescription, entry.metadata().keyId());
            return Optional.of(sessionKey);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            log.warn("Failed to decrypt session key using {}: {}", keyDescription, entry.metadata().keyId(), e);
            return Optional.empty();
        } catch (GeneralSecurityException e) {
            throw new CryptoServerSideException("Failed to initialize RSA session key decryption", e);
        }
    }

    private Optional<SecretKey> decryptWithLatestVaultKey(
            String encryptedSessionKeyBase64,
            String requestedAlias,
            KeyRing.KeyEntry activeEntry
    ) {
        if (!(keyRing instanceof VaultKeyRing vaultKeyRing)) {
            return Optional.empty();
        }
        try {
            KeyRing.KeyEntry latestEntry = vaultKeyRing.syncLatestKeyFromVault(requestedAlias);
            if (latestEntry == null || isActiveKey(latestEntry, activeEntry)) {
                return Optional.empty();
            }
            return tryDecryptSessionKey(encryptedSessionKeyBase64, latestEntry, "latest Vault key");
        } catch (GeneralSecurityException | IOException | IllegalStateException e) {
            throw new CryptoServerSideException("Failed to synchronize the latest decryption key from Vault", e);
        }
    }

    private boolean isActiveKey(KeyRing.KeyEntry entry, KeyRing.KeyEntry activeEntry) {
        return activeEntry != null && entry.metadata().keyId().equals(activeEntry.metadata().keyId());
    }

    private RuntimeException sessionKeyDecryptionFailure(
            String keyId,
            String requestedAlias,
            Optional<KeyRing.KeyEntry> requestedEntry
    ) {
        throwIfKeyExpired(keyId, requestedAlias, requestedEntry);
        log.warn("Failed to decrypt session key with keyId={}, all known keys exhausted", keyId);
        return new SessionKeyDecryptionException(
                "Failed to decrypt session key: keyId may be expired, unknown, or ciphertext invalid.");
    }

    private void throwIfKeyExpired(
            String keyId,
            String requestedAlias,
            Optional<KeyRing.KeyEntry> requestedEntry
    ) {
        if (requestedAlias == null) {
            return;
        }
        KeyRing.KeyEntry activeEntry = keyRing.findActiveKeyEntry(requestedAlias).orElseThrow(InvalidKeyException::new);
        KeyMetadata requestedMetadata = new KeyMetadata(keyId, 0, 0);
        Long requestedVersion = requestedMetadata.version();
        Long activeVersion = activeEntry.metadata().version();
        if (requestedEntry.isEmpty()
                && (requestedVersion == null || !requestedVersion.equals(activeVersion))) {
            throw new KeyExpiredException(getPublicKey(activeEntry.metadata().keyAlias()));
        }
    }

    public void validatePayload(CipherRequestPayload payload) {
        if (payload == null) {
            throw new InvalidCryptoRequestException("Encrypted request payload is required but was not provided.");
        }
        if (!StringUtils.hasLength(payload.ivBase64())) {
            throw new InvalidCryptoRequestException("IV is required but was not provided.");
        }
        if (!StringUtils.hasLength(payload.encryptedDataBase64())) {
            throw new InvalidCryptoRequestException("Encrypted data is required but was not provided.");
        }
    }

    private String decryptWithAes(CipherRequestPayload payload, SecretKey sessionKey) throws GeneralSecurityException {
        byte[] encryptedData;
        byte[] iv;
        try {
            encryptedData = EncodingUtils.fromBase64(payload.encryptedDataBase64());
            iv = EncodingUtils.fromBase64(payload.ivBase64());
        } catch (IllegalArgumentException e) {
            throw new InvalidCryptoRequestException("Invalid Base64 format in encrypted data or IV.", e);
        }
        if (iv.length != CryptoConstants.GCM_IV_LENGTH_BYTES) {
            throw new InvalidCryptoRequestException("IV must contain exactly 12 bytes.");
        }
        if (encryptedData.length < CryptoConstants.GCM_TAG_LENGTH_BITS / Byte.SIZE) {
            throw new InvalidCryptoRequestException("Encrypted data must include a 16-byte GCM authentication tag.");
        }
        try {
            return new String(AesGcmCipher.decrypt(encryptedData, sessionKey, iv), StandardCharsets.UTF_8);
        } catch (BadPaddingException e) {
            log.warn("GCM authentication tag verification failed, ciphertext may have been tampered with or corrupted");
            throw new DataTamperedException("Encrypted data authentication failed: data corrupted or tampered with.", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoServerSideException("Failed to initialize AES request decryption", e);
        }
    }
}
