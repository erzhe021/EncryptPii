package com.ikea.crypto.stc.model;

/**
 * KeyMetadata represents the lifecycle and identity of an asymmetric key pair.
 */
public record KeyMetadata(
        String keyId,
        long createdAtEpochMillis,
        long expiresAtEpochMillis
) {
    public static final String DEFAULT_KEY_ALIAS = "pii-transport-key";

    public static String buildKeyId(String keyAlias, long version) {
        String alias = (keyAlias != null && !keyAlias.isBlank()) ? keyAlias.trim() : DEFAULT_KEY_ALIAS;
        return alias + ":" + version;
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
            } catch (NumberFormatException ignored) {
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
