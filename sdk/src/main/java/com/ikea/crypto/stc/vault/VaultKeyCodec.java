package com.ikea.crypto.stc.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.model.KeyMetadata;
import com.ikea.crypto.stc.util.EncodingUtils;
import com.ikea.crypto.stc.key.KeyRing;
import lombok.extern.slf4j.Slf4j;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Handles serialization and deserialization between Java RSA cryptographic keys
 * and Vault KV JSON representation.
 */
@Slf4j
public class VaultKeyCodec {

    private final KeyFactory keyFactory;

    public VaultKeyCodec() {
        try {
            this.keyFactory = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA algorithm not available", e);
        }
    }

    /**
     * Serializes an RSA KeyPair into key-value map for Vault storage.
     */
    public Map<String, Object> serializeKeyPair(KeyPair keyPair) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("publicKey", EncodingUtils.toBase64(keyPair.getPublic().getEncoded()));
        payload.put("privateKey", EncodingUtils.toBase64(keyPair.getPrivate().getEncoded()));
        return payload;
    }

    /**
     * Deserializes a Vault JSON data node into a KeyRing.KeyEntry.
     */
    public KeyRing.KeyEntry deserializeKeyEntry(
            JsonNode dataNode,
            int version,
            String createdTimeStr,
            String keyAlias,
            long validityMillis
    ) throws GeneralSecurityException {
        long createdAt = parseCreatedTime(createdTimeStr, System.currentTimeMillis());
        long expiresAt = createdAt + validityMillis;
        String keyId = KeyMetadata.buildKeyId(keyAlias, version);

        String pubBase64 = dataNode.path("publicKey").asText();
        String privBase64 = dataNode.path("privateKey").asText();
        if (pubBase64.isBlank() || privBase64.isBlank()) {
            throw new IllegalArgumentException("publicKey and privateKey must not be empty in Vault secret version " + version);
        }

        byte[] pubBytes = EncodingUtils.fromBase64(pubBase64);
        byte[] privBytes = EncodingUtils.fromBase64(cleanPrivKeyBase64(privBase64));

        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
        KeyPair keyPair = new KeyPair(publicKey, privateKey);

        KeyMetadata metadata = new KeyMetadata(keyId, createdAt, expiresAt);
        return new KeyRing.KeyEntry(metadata, keyPair);
    }

    /**
     * Parses ISO-8601 created time from Vault metadata into epoch milliseconds.
     */
    public long parseCreatedTime(String createdTimeStr, long defaultTime) {
        if (createdTimeStr != null && !createdTimeStr.isBlank()) {
            try {
                return Instant.parse(createdTimeStr).toEpochMilli();
            } catch (Exception ignored) {
            }
        }
        return defaultTime;
    }

    private String cleanPrivKeyBase64(String priv) {
        return priv.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
    }
}
