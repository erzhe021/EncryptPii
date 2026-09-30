package com.ikea.crypto.stc.key;

import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.SessionKeyService;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.KeyMetadata;
import com.ikea.crypto.stc.model.PublicKeyResponse;
import com.ikea.crypto.stc.util.EncodingUtils;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import com.ikea.crypto.stc.exception.DataTamperedException;
import com.ikea.crypto.stc.exception.InvalidCryptoPayloadException;
import com.ikea.crypto.stc.exception.KeyNotAvailableException;
import com.ikea.crypto.stc.exception.SessionKeyDecryptionException;
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
import java.util.Optional;

@Slf4j
public record CryptoServer(KeyRing keyRing) {

    /**
     * Backward-compatible constructor using a single static keypair with 1 year validity.
     */
    public CryptoServer(PrivateKey privateKey, PublicKey publicKey) {
        this(createInMemoryKeyRing(privateKey, publicKey));
    }

    private static KeyRing createInMemoryKeyRing(PrivateKey privateKey, PublicKey publicKey) {
        String keyAlias = "in-memory-test-key";
        String keyId = KeyMetadata.buildKeyId(keyAlias, 1);
        long now = System.currentTimeMillis();
        long expiresAt = now + 365L * 24 * 60 * 60 * 1000;
        KeyMetadata metadata = new KeyMetadata(keyId, now, expiresAt);
        KeyRing.KeyEntry entry = new KeyRing.KeyEntry(metadata, new KeyPair(publicKey, privateKey));

        KeyRing ring = new KeyRing(keyAlias);
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
        if (active.metadata().isExpired()) {
            log.warn("Active key: keyId={} has expired, start to rotate to a new key version", active.metadata().keyId());
            return rotateKey();
        }

        return new PublicKeyResponse(
                EncodingUtils.toBase64(active.publicKey().getEncoded()),
                active.metadata().keyId(),
                active.metadata().expiresAtEpochMillis()
        );
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
        return new PublicKeyResponse(
                EncodingUtils.toBase64(entry.publicKey().getEncoded()),
                entry.metadata().keyId(),
                entry.metadata().expiresAtEpochMillis()
        );
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
            return new PublicKeyResponse(
                    EncodingUtils.toBase64(newEntry.publicKey().getEncoded()),
                    newEntry.metadata().keyId(),
                    newEntry.metadata().expiresAtEpochMillis()
            );
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
            return new PublicKeyResponse(
                    EncodingUtils.toBase64(newEntry.publicKey().getEncoded()),
                    newEntry.metadata().keyId(),
                    newEntry.metadata().expiresAtEpochMillis()
            );
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

        // 1. If keyId is provided, try that specific key first
        if (keyId != null && !keyId.isBlank()) {
            Optional<KeyRing.KeyEntry> entryOpt = keyRing.findKeyEntry(keyId);
            if (entryOpt.isPresent()) {
                try {
                    return SessionKeyService.decryptSessionKeyBase64(encryptedSessionKeyBase64, entryOpt.get().privateKey());
                } catch (GeneralSecurityException e) {
                    log.warn("Failed to decrypt session key with matched keyId={}, attempting keyring fallback", keyId, e);
                }
            }
        }

        // 2. Try the active key
        KeyRing.KeyEntry activeEntry = keyRing.getActiveKeyEntry();
        if (activeEntry != null) {
            try {
                return SessionKeyService.decryptSessionKeyBase64(encryptedSessionKeyBase64, activeEntry.privateKey());
            } catch (GeneralSecurityException e) {
                log.warn("Decryption with active key failed, trying historical transition keys in keyring...", e);
            }
        }

        // 3. Fallback across all available keys (grace period support for old clients during rotation)
        for (KeyRing.KeyEntry entry : keyRing.getAllKeyEntries()) {
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
                KeyRing.KeyEntry latestEntry = vaultKeyRing.syncLatestKeyFromVault();
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
