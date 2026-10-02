package com.ikea.crypto.stc.key;

import com.fasterxml.jackson.databind.JsonNode;
import com.ikea.crypto.stc.config.VaultProperties;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.model.VerificationKeyResponse;
import com.ikea.crypto.stc.util.EncodingUtils;
import com.ikea.crypto.stc.vault.VaultAuthenticator;
import com.ikea.crypto.stc.vault.VaultClient;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Slf4j
public class EcdsaSigningService {

    @Getter
    private volatile PrivateKey privateKey;
    @Getter
    private volatile PublicKey publicKey;
    private final VaultProperties vaultProperties;
    private final VaultClient vaultClient;
    private final String vaultToken;
    private final String secretPath;
    private final ScheduledExecutorService rotationScheduler;

    public EcdsaSigningService(PrivateKey privateKey, PublicKey publicKey) {
        this(privateKey, publicKey, null, null, null, null);
    }

    private EcdsaSigningService(PrivateKey privateKey, PublicKey publicKey,
                                VaultProperties vaultProperties, VaultClient vaultClient,
                                String vaultToken, String secretPath) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.vaultProperties = vaultProperties;
        this.vaultClient = vaultClient;
        this.vaultToken = vaultToken;
        this.secretPath = secretPath;
        this.rotationScheduler = vaultProperties != null && vaultProperties.isAutoRotate()
                ? Executors.newSingleThreadScheduledExecutor(r -> {
                    Thread t = new Thread(r, "ecdsa-signing-rotation");
                    t.setDaemon(true);
                    return t;
                })
                : null;
        if (rotationScheduler != null) {
            long interval = Math.max(5_000L, vaultProperties.getRotationCheckIntervalMillis());
            rotationScheduler.scheduleAtFixedRate(this::refreshIfNeeded, interval, interval, TimeUnit.MILLISECONDS);
        }
    }

    public static EcdsaSigningService fromVault(VaultProperties properties)
            throws GeneralSecurityException, IOException {
        VaultClient client = new VaultClient(properties.getAddr());
        VaultAuthenticator authenticator = new VaultAuthenticator(properties, client);
        String token = authenticator.authenticate();
        String secretPath = normalizeSecretPath(properties.getEcdsaSecretPath());
        ensureRequiredSecretsPresent(client, token, properties);
        PrivateKey privateKey = loadPrivateKeyFromVault(client, token, secretPath, "privateKey");
        PublicKey publicKey = loadPublicKeyFromVault(client, token, secretPath, "publicKey");
        return new EcdsaSigningService(privateKey, publicKey, properties, client, token, secretPath);
    }

    public byte[] sign(byte[] payload) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA);
        signature.initSign(privateKey);
        signature.update(payload);
        return signature.sign();
    }

    public VerificationKeyResponse toVerificationKeyResponse() {
        String keyId = "ecdsa-20261001";
        long expiresAt = System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000;
        return new VerificationKeyResponse(
                EncodingUtils.toBase64(publicKey.getEncoded()),
                keyId,
                expiresAt
        );
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
            KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
            generator.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
            KeyPair pair = generator.generateKeyPair();
            Map<String, Object> payload = new HashMap<>();
            payload.put("privateKey", EncodingUtils.toBase64(pair.getPrivate().getEncoded()));
            payload.put("publicKey", EncodingUtils.toBase64(pair.getPublic().getEncoded()));
            vaultClient.writeSecret(vaultToken, secretPath, payload);
            this.privateKey = pair.getPrivate();
            this.publicKey = pair.getPublic();
            log.info("Auto-rotated Vault ECDSA key at path {}", secretPath);
        } catch (Exception e) {
            log.warn("Failed to rotate Vault ECDSA key at {}: {}", secretPath, e.getMessage());
        }
    }

    public void shutdown() {
        if (rotationScheduler != null && !rotationScheduler.isShutdown()) {
            rotationScheduler.shutdownNow();
        }
    }

    private static void ensureRequiredSecretsPresent(VaultClient client, String vaultToken, VaultProperties properties)
            throws GeneralSecurityException {
        String ecdsaPath = normalizeSecretPath(properties.getEcdsaSecretPath());
        boolean ecdsaMissing = client.readSecret(vaultToken, ecdsaPath).isEmpty();
        if (!ecdsaMissing) {
            return;
        }
        if (!properties.isAutoBootstrap()) {
            throw new IllegalStateException("Vault secret missing and auto-bootstrap disabled: " + ecdsaPath);
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        generator.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        KeyPair pair = generator.generateKeyPair();

        Map<String, Object> payload = new HashMap<>();
        payload.put("privateKey", EncodingUtils.toBase64(pair.getPrivate().getEncoded()));
        payload.put("publicKey", EncodingUtils.toBase64(pair.getPublic().getEncoded()));
        client.writeSecret(vaultToken, ecdsaPath, payload);
    }

    private static PrivateKey loadPrivateKeyFromVault(VaultClient client, String vaultToken, String secretPath, String keyFieldName)
            throws GeneralSecurityException {
        JsonNode secret = client.readSecret(vaultToken, secretPath)
                .orElseThrow(() -> new IllegalStateException("Vault secret not found: " + secretPath));
        String keyBase64 = readKeyFromNode(secret, keyFieldName, "privateKey");
        return KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC)
                .generatePrivate(new PKCS8EncodedKeySpec(EncodingUtils.fromBase64(keyBase64)));
    }

    private static PublicKey loadPublicKeyFromVault(VaultClient client, String vaultToken, String secretPath, String keyFieldName)
            throws GeneralSecurityException {
        JsonNode secret = client.readSecret(vaultToken, secretPath)
                .orElseThrow(() -> new IllegalStateException("Vault secret not found: " + secretPath));
        String keyBase64 = readKeyFromNode(secret, keyFieldName, "publicKey");
        return KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC)
                .generatePublic(new X509EncodedKeySpec(EncodingUtils.fromBase64(keyBase64)));
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
            return "sensitive-transport-crypto/ecdsa-ciam";
        }
        String normalized = secretPath.trim();
        return normalized.startsWith("/") ? normalized.substring(1) : normalized;
    }
}
