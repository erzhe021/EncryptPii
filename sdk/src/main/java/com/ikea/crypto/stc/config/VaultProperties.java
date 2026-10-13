package com.ikea.crypto.stc.config;

import jakarta.validation.constraints.Min;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

/**
 * Configuration properties for Vault integration in sensitive transport crypto functionality.
 * <p>
 * These properties can be set in the application's configuration files (e.g., application.properties or application.yml)
 * to customize the behavior of Vault integration for key management and retrieval.
 * </p>
 */
@Data
@Validated
public class VaultProperties {

    /**
     * Whether Vault key management is enabled. Defaults to false.
     */
    private boolean enabled = false;

    /**
     * Vault KV v2 secret path (relative to /v1/), e.g. secret/data/sensitive-transport-crypto/demo-service
     */
    private String secretPath = "replace-with-your-vault-secret-path";

    /**
     * Logical key alias used in keyId format <keyAlias>:<version>.
     */
    private String keyAlias = "replace-with-your-key-alias";

    /**
     * Automatically bootstrap and initialize keys in Vault if none exist.
     */
    private boolean autoBootstrap = true;

    /**
     * Wait time in milliseconds for pods that lost CAS competition before re-fetching the updated key from Vault.
     * Default: 1200ms (1~2 seconds).
     */
    @Min(value = 0, message = "cas-backoff-millis must not be negative")
    private long casBackoffMillis = 1200L;

    /**
     * Maximum number of attempts to poll Vault after CAS competition loss.
     */
    @Min(value = 1, message = "cas-max-retries must be greater than zero")
    private int casMaxRetries = 3;

    /**
     * Interval in milliseconds between retries when polling Vault after CAS conflict.
     */
    @Min(value = 1, message = "cas-retry-interval-millis must be greater than zero")
    private long casRetryIntervalMillis = 500L;

}
