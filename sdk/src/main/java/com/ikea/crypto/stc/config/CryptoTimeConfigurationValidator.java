package com.ikea.crypto.stc.config;

/**
 * Validates the timing configuration for key lifecycle management in sensitive transport crypto.
 * <p>
 * Ensures that the grace period is less than the rotation window, which is less than the key validity duration.
 * </p>
 */
public final class CryptoTimeConfigurationValidator {

    /**
     * Validates the timing configuration for key lifecycle management in sensitive transport crypto.
     *
     * @param cryptoProperties the sensitive transport crypto properties containing key lifecycle settings
     * @throws IllegalArgumentException if the timing configuration is invalid
     */
    public CryptoTimeConfigurationValidator(SensitiveTransportCryptoProperties cryptoProperties) {
        KeyLifecycleProperties lifecycleProperties = cryptoProperties.getKeyLifecycle();
        long keyValidityMillis = lifecycleProperties.getValidityMillis();
        long gracePeriodMillis = lifecycleProperties.getGracePeriodMillis();
        long rotationWindowMillis = lifecycleProperties.getRotationBeforeExpiryMillis();

        if (!(gracePeriodMillis < rotationWindowMillis && rotationWindowMillis < keyValidityMillis)) {
            throw new IllegalArgumentException(
                    "Crypto timing configuration must satisfy grace-period-millis < "
                            + "rotation-before-expiry-millis < key validity: "
                            + gracePeriodMillis + " < " + rotationWindowMillis + " < " + keyValidityMillis
            );
        }
    }
}
