package com.ikea.crypto.stc.config;

import jakarta.validation.Valid;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Configuration vaultProperties for sensitive transport crypto functionality.
 * <p>
 * These vaultProperties can be set in the application's configuration files (e.g., application.vaultProperties or application.yml)
 * to customize the behavior of the sensitive transport crypto features.
 * </p>
 */
@Data
@Validated
@ConfigurationProperties(prefix = "sensitive.transport.crypto")
public class SensitiveTransportCryptoProperties {

    /**
     * Whether sensitive transport crypto functionality is enabled. Defaults to true.
     */
    private boolean enabled = true;

    /**
     * Whether expired keys are rotated automatically. Defaults to true.
     */
    private boolean autoRotate = true;

    /**
     * Key validity, rotation, and transition grace-period configuration.
     */
    @Valid
    private KeyLifecycleProperties keyLifecycle = new KeyLifecycleProperties();

    /**
     * Vault integration and key storage configuration.
     */
    @Valid
    private VaultProperties vault = new VaultProperties();

    /**
     * Endpoint configuration for public key retrieval.
     */
    @Valid
    private EndpointProperties endpoint = new EndpointProperties();

    @Data
    public static class EndpointProperties {
        /**
         * Whether to expose public key REST endpoints.
         * Default is true.
         */
        private boolean enabled = true;

        /**
         * Base path for public key endpoints.
         * Default is /sensitive-transport-crypto.
         */
        private String basePath = "/sensitive-transport-crypto";
    }

}
