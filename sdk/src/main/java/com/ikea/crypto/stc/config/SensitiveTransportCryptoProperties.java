package com.ikea.crypto.stc.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for sensitive transport crypto functionality.
 * <p>
 * These properties can be set in the application's configuration files (e.g., application.properties or application.yml)
 * to customize the behavior of the sensitive transport crypto features.
 * </p>
 */
@Data
@ConfigurationProperties(prefix = "sensitive.transport.crypto")
public class SensitiveTransportCryptoProperties {

    /**
     * Whether sensitive transport crypto functionality is enabled. Defaults to true.
     */
    private boolean enabled = true;

    /**
     * Endpoint configuration for public key retrieval.
     */
    private EndpointProperties endpoint = new EndpointProperties();

    @Data
    public static class EndpointProperties {
        /**
         * Whether to expose public key REST endpoints.
         * Default is true.
         */
        private boolean enabled = true;

        /**
         * Base path for server crypto endpoints.
         * Default is /crypto/server.
         */
        private String basePath = "/crypto/server";
    }

}
