package com.ikea.crypto.server.service;

import com.ikea.crypto.common.crypto.AesGcmCryptoService;
import com.ikea.crypto.common.crypto.SessionKeyService;
import com.ikea.crypto.common.model.payload.CipherRequestPayload;
import com.ikea.crypto.common.model.payload.KeyMetadata;
import com.ikea.crypto.common.model.payload.PublicKeyResponse;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Path;
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
        String keyId = "rsa-20261001";
        long now = System.currentTimeMillis();
        long expiresAt = now + 365L * 24 * 60 * 60 * 1000;
        KeyMetadata metadata = new KeyMetadata(keyId, now, expiresAt);
        KeyRing.KeyEntry entry = new KeyRing.KeyEntry(metadata, new KeyPair(publicKey, privateKey));

        return new KeyRing(Path.of(".")) {
            @Override
            public KeyEntry getActiveKeyEntry() {
                return entry;
            }

            @Override
            public Optional<KeyEntry> findKeyEntry(String requestedKeyId) {
                return Optional.of(entry);
            }
        };
    }

    public PublicKey publicKey() {
        return keyRing.getActiveKeyEntry().publicKey();
    }

    public PrivateKey privateKey() {
        return keyRing.getActiveKeyEntry().privateKey();
    }

    /**
     * Returns the active RSA public key for clients.
     */
    public PublicKeyResponse getPublicKey() {
        KeyRing.KeyEntry active = keyRing.getActiveKeyEntry();
        if (active == null) {
            throw new IllegalStateException("No active RSA key in keyring");
        }
        return new PublicKeyResponse(
                EncodingUtils.toBase64(active.publicKey().getEncoded()),
                active.metadata().keyId(),
                active.metadata().expiresAtEpochMillis()
        );
    }

    public static CryptoServer create(Path keyDirectory) throws GeneralSecurityException, IOException {
        log.info("Creating CryptoServer from keyDirectory={}", keyDirectory);
        KeyRing keyRing = new KeyRing(keyDirectory);
        keyRing.initialize();
        return new CryptoServer(keyRing);
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

    public byte[] decryptSessionKey(String encryptedSessionKeyBase64) throws GeneralSecurityException {
        return decryptSessionKey(null, encryptedSessionKeyBase64);
    }

    public byte[] decryptSessionKey(String keyId, String encryptedSessionKeyBase64) throws GeneralSecurityException {
        return decryptSessionKeyToSecretKey(keyId, encryptedSessionKeyBase64).getEncoded();
    }

    public SecretKey decryptSessionKeyToSecretKey(String encryptedSessionKeyBase64) throws GeneralSecurityException {
        return decryptSessionKeyToSecretKey(null, encryptedSessionKeyBase64);
    }

    /**
     * Decrypts the encrypted session key using the private key corresponding to keyId,
     * or attempts all available keys in the transition grace period if keyId is not matched/provided.
     */
    public SecretKey decryptSessionKeyToSecretKey(String keyId, String encryptedSessionKeyBase64) throws GeneralSecurityException {
        log.debug("start to decrypt session key, keyId={}, from encryptedSessionKeyBase64", keyId);
        if (!StringUtils.hasLength(encryptedSessionKeyBase64)) {
            throw new IllegalArgumentException("Encrypted session key is required.");
        }

        // 1. If keyId is provided, try that specific key first
        if (keyId != null && !keyId.isBlank()) {
            Optional<KeyRing.KeyEntry> entryOpt = keyRing.findKeyEntry(keyId);
            if (entryOpt.isPresent()) {
                try {
                    return SessionKeyService.decryptSessionKeyBase64(encryptedSessionKeyBase64, entryOpt.get().privateKey());
                } catch (GeneralSecurityException e) {
                    log.warn("Failed to decrypt session key with matched keyId={}, attempting keyring fallback", keyId);
                }
            }
        }

        // 2. Try the active key
        KeyRing.KeyEntry activeEntry = keyRing.getActiveKeyEntry();
        if (activeEntry != null) {
            try {
                return SessionKeyService.decryptSessionKeyBase64(encryptedSessionKeyBase64, activeEntry.privateKey());
            } catch (GeneralSecurityException e) {
                log.debug("Decryption with active key failed, trying historical transition keys in keyring...");
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
            } catch (GeneralSecurityException ignored) {
                // Try next historical key
            }
        }

        throw new GeneralSecurityException("Unable to decrypt session key with any available RSA keys in keyring.");
    }

    public void validatePayload(CipherRequestPayload payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Payload cannot be null");
        }
        if (!StringUtils.hasLength(payload.encryptedSessionKeyBase64())) {
            throw new IllegalArgumentException("Encrypted AES key is required for RSA decryption but was not provided.");
        }
        if (!StringUtils.hasLength(payload.ivBase64())) {
            throw new IllegalArgumentException("IV is required but was not provided.");
        }
        if (!StringUtils.hasLength(payload.encryptedDataBase64())) {
            throw new IllegalArgumentException("Encrypted data is required but was not provided.");
        }
    }

    private String decryptWithAes(CipherRequestPayload payload, SecretKey sessionKey) throws GeneralSecurityException {
        return AesGcmCryptoService.decryptFromBase64(
                payload.encryptedDataBase64(),
                sessionKey,
                payload.ivBase64()
        );
    }
}
