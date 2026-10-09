package com.ikea.crypto.stc.config;

import com.ikea.crypto.stc.key.KeyRing;

public final class CryptoTimeConfigurationValidator {

    public CryptoTimeConfigurationValidator(
            KeyLifecycleProperties lifecycleProperties
    ) {
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
