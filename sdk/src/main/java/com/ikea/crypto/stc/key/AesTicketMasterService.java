package com.ikea.crypto.stc.key;

import com.fasterxml.jackson.databind.JsonNode;
import com.ikea.crypto.stc.config.VaultProperties;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.stc.util.EncodingUtils;
import com.ikea.crypto.stc.vault.VaultAuthenticator;
import com.ikea.crypto.stc.vault.VaultClient;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Slf4j
public class AesTicketMasterService {

    @Getter
    private volatile SecretKey ticketMasterKey;
    private final VaultProperties vaultProperties;
    private final VaultClient vaultClient;
    private final String vaultToken;
    private final String secretPath;
    private final ScheduledExecutorService rotationScheduler;

    public AesTicketMasterService(SecretKey ticketMasterKey) {
        this(ticketMasterKey, null, null, null, null);
    }

    private AesTicketMasterService(SecretKey ticketMasterKey, VaultProperties vaultProperties,
                                  VaultClient vaultClient, String vaultToken, String secretPath) {
        this.ticketMasterKey = ticketMasterKey;
        this.vaultProperties = vaultProperties;
        this.vaultClient = vaultClient;
        this.vaultToken = vaultToken;
        this.secretPath = secretPath;
        this.rotationScheduler = vaultProperties != null && vaultProperties.isAutoRotate()
                ? Executors.newSingleThreadScheduledExecutor(r -> {
                    Thread t = new Thread(r, "aes-ticket-rotation");
                    t.setDaemon(true);
                    return t;
                })
                : null;
        if (rotationScheduler != null) {
            long interval = Math.max(5_000L, vaultProperties.getRotationCheckIntervalMillis());
            rotationScheduler.scheduleAtFixedRate(this::refreshIfNeeded, interval, interval, TimeUnit.MILLISECONDS);
        }
    }

    public static AesTicketMasterService fromVault(VaultProperties properties)
            throws GeneralSecurityException, IOException, InterruptedException {
        VaultClient client = new VaultClient(properties.getAddr());
        VaultAuthenticator authenticator = new VaultAuthenticator(properties, client);
        String token = authenticator.authenticate();
        String secretPath = normalizeSecretPath(properties.getAesSecretPath());
        ensureRequiredSecretsPresent(client, token, properties);
        SecretKey key = loadMasterKeyFromVault(client, token, secretPath);
        return new AesTicketMasterService(key, properties, client, token, secretPath);
    }

    public String packEphemeralPrivateKeyToTicket(java.security.PrivateKey privateKey, Duration ttl) throws GeneralSecurityException {
        byte[] privateKeyBytes = privateKey.getEncoded();
        long expiresAt = System.currentTimeMillis() + ttl.toMillis();
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES + privateKeyBytes.length);
        buffer.putLong(expiresAt);
        buffer.put(privateKeyBytes);
        byte[] iv = CryptoSessionMaterialFactory.generateIv(new java.security.SecureRandom());
        byte[] ciphertext = AesGcmCipher.encrypt(buffer.array(), ticketMasterKey, iv);
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        return EncodingUtils.toBase64(combined);
    }

    public java.security.PrivateKey unpackEphemeralPrivateKeyFromTicket(String serverKeyTicketBase64) throws GeneralSecurityException {
        if (!StringUtils.hasLength(serverKeyTicketBase64)) {
            throw new IllegalArgumentException("Key ticket is required for stateless ECDH decryption but was not provided.");
        }
        byte[] combined = EncodingUtils.fromBase64(serverKeyTicketBase64);
        if (combined.length < 12 + 16 + Long.BYTES) {
            throw new IllegalArgumentException("Invalid key ticket format");
        }
        byte[] iv = Arrays.copyOfRange(combined, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(combined, 12, combined.length);
        byte[] plaintext = AesGcmCipher.decrypt(ciphertext, ticketMasterKey, iv);
        ByteBuffer buffer = ByteBuffer.wrap(plaintext);
        long expiresAt = buffer.getLong();
        if (System.currentTimeMillis() > expiresAt) {
            throw new IllegalArgumentException("Ephemeral key ticket has expired");
        }
        byte[] privateKeyBytes = new byte[buffer.remaining()];
        buffer.get(privateKeyBytes);
        return KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC)
                .generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
    }

    public void refreshIfNeeded() {
        if (vaultProperties == null || vaultClient == null || vaultToken == null || secretPath == null) {
            return;
        }
        try {
            JsonNode secret = vaultClient.readSecret(vaultToken, secretPath).orElse(null);
            if (secret == null) {
                return;
            }
            long rotatedAt = readRotatedAtEpochMillis(secret, System.currentTimeMillis());
            if (System.currentTimeMillis() - rotatedAt < vaultProperties.getValidityMillis()) {
                return;
            }
            KeyGenerator generator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
            generator.init(CryptoConstants.AES_KEY_SIZE_BITS);
            SecretKey newKey = generator.generateKey();
            Map<String, Object> payload = new HashMap<>();
            byte[] bytes = newKey.getEncoded();
            payload.put("masterKey", EncodingUtils.toBase64(bytes));
            vaultClient.writeSecret(vaultToken, secretPath, payload);
            this.ticketMasterKey = newKey;
            log.info("Auto-rotated Vault AES ticket key at path {}", secretPath);
        } catch (Exception e) {
            log.warn("Failed to rotate Vault AES ticket key at {}: {}", secretPath, e.getMessage());
        }
    }

    public void shutdown() {
        if (rotationScheduler != null && !rotationScheduler.isShutdown()) {
            rotationScheduler.shutdownNow();
        }
    }

    private static void ensureRequiredSecretsPresent(VaultClient client, String vaultToken, VaultProperties properties)
            throws GeneralSecurityException {
        String aesPath = normalizeSecretPath(properties.getAesSecretPath());
        boolean aesMissing = client.readSecret(vaultToken, aesPath).isEmpty();
        if (!aesMissing) {
            return;
        }
        if (!properties.isAutoBootstrap()) {
            throw new IllegalStateException("Vault secret missing and auto-bootstrap disabled: " + aesPath);
        }
        KeyGenerator generator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        generator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey key = generator.generateKey();
        byte[] bytes = key.getEncoded();
        Map<String, Object> payload = new HashMap<>();
        payload.put("masterKey", EncodingUtils.toBase64(bytes));
        client.writeSecret(vaultToken, aesPath, payload);
    }

    private static SecretKey loadMasterKeyFromVault(VaultClient client, String vaultToken, String secretPath) {
        JsonNode secret = client.readSecret(vaultToken, secretPath)
                .orElseThrow(() -> new IllegalStateException("Vault secret not found: " + secretPath));
        String keyBase64 = readKeyFromNode(secret, "masterKey");
        byte[] keyBytes = EncodingUtils.fromBase64(keyBase64);
        return new SecretKeySpec(keyBytes, CryptoConstants.ALGORITHM_AES);
    }

    private static long readRotatedAtEpochMillis(JsonNode secret, long defaultValue) {
        JsonNode node = secret.get("rotatedAtEpochMillis");
        if (node != null && !node.isNull() && node.asText() != null && !node.asText().isBlank()) {
            try {
                return Long.parseLong(node.asText());
            } catch (NumberFormatException ignored) {
            }
        }
        return defaultValue;
    }

    private static String readKeyFromNode(JsonNode secret, String... fieldNames) {
        for (String fieldName : fieldNames) {
            JsonNode value = secret.get(fieldName);
            if (value != null && !value.isNull() && !value.asText().isBlank()) {
                return value.asText();
            }
        }
        throw new IllegalStateException("Vault secret is missing one of: " + String.join(", ", fieldNames));
    }

    private static String normalizeSecretPath(String secretPath) {
        if (secretPath == null || secretPath.isBlank()) {
            return "sensitive-transport-crypto/aes-ciam";
        }
        String normalized = secretPath.trim();
        return normalized.startsWith("/") ? normalized.substring(1) : normalized;
    }
}
