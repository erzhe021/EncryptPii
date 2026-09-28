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
        return isExpired(System.currentTimeMillis());
    }

    public boolean isExpired(long now) {
        return now >= expiresAtEpochMillis;
    }

    public boolean isGracePeriodExpired(long gracePeriodMillis, long now) {
        return now >= expiresAtEpochMillis + gracePeriodMillis;
    }

    public boolean isWithinGracePeriod(long gracePeriodMillis, long now) {
        return isExpired(now) && !isGracePeriodExpired(gracePeriodMillis, now);
    }
}
