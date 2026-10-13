package com.ikea.crypto.stc.model;

import lombok.extern.slf4j.Slf4j;

/**
 * Represents metadata for a cryptographic key, including its identifier, creation time, and expiration time.
 *
 * @param keyId                The unique identifier for the key, typically in the format "keyAlias:version".
 * @param createdAtEpochMillis The epoch time in milliseconds when the key was created.
 * @param expiresAtEpochMillis The epoch time in milliseconds when the key will expire.
 */
@Slf4j
public record KeyMetadata(
        String keyId,
        long createdAtEpochMillis,
        long expiresAtEpochMillis
) {

    public static String buildKeyId(String keyAlias, long version) {
        return keyAlias + ":" + version;
    }

    public String keyAlias() {
        if (keyId != null && keyId.contains(":")) {
            return keyId.substring(0, keyId.indexOf(':'));
        }
        return keyId;
    }

    public Long version() {
        if (keyId != null && keyId.contains(":")) {
            try {
                return Long.parseLong(keyId.substring(keyId.indexOf(':') + 1));
            } catch (NumberFormatException e) {
                log.warn("Cannot parse key version: keyId={}", keyId, e);
                return null;
            }
        }
        return null;
    }

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
