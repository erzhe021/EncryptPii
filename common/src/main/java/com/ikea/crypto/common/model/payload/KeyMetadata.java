package com.ikea.crypto.common.model.payload;

/**
 * KeyMetadata represents the lifecycle and identity of an asymmetric key pair.
 */
public record KeyMetadata(
        String keyId,
        long createdAtEpochMillis,
        long expiresAtEpochMillis
) {
    public boolean isExpired() {
        return System.currentTimeMillis() >= expiresAtEpochMillis;
    }
}
