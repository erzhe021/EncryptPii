package com.ikea.crypto.stc.config;

import jakarta.validation.constraints.Min;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configuration for key validity, proactive rotation, and transition grace periods.
 */
@Data
@Validated
@ConfigurationProperties(prefix = "sensitive.transport.crypto.key-lifecycle")
public class KeyLifecycleProperties {

    /**
     * Key validity duration in milliseconds.
     */
    @Min(value = 1, message = "validity-millis must be greater than zero")
    private long validityMillis = 365L * 24 * 60 * 60 * 1000;

    /**
     * Rotate keys when their remaining validity falls below this window.
     */
    @Min(value = 0, message = "rotation-before-expiry-millis must not be negative")
    private long rotationBeforeExpiryMillis = 30L * 24 * 60 * 60 * 1000;

    /**
     * Grace period in milliseconds after a replacement key is activated.
     */
    @Min(value = 0, message = "grace-period-millis must not be negative")
    private long gracePeriodMillis = 1L * 24 * 60 * 60 * 1000;

}
