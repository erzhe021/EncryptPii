package com.ikea.crypto.server.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "crypto.server")
public class CryptoServerProperties {

    /**
     * Whether server-side encryption/decryption SDK is enabled.
     * Default is true.
     */
    private boolean enabled = true;

    /**
     * Endpoint configuration for public key and key rotation.
     */
    private EndpointProperties endpoint = new EndpointProperties();

    /**
     * Global exception handler configuration.
     */
    private ExceptionHandlerProperties exceptionHandler = new ExceptionHandlerProperties();

    @Data
    public static class EndpointProperties {
        /**
         * Whether to expose public key and rotation REST endpoints.
         * Default is true.
         */
        private boolean enabled = true;

        /**
         * Base path for server crypto endpoints.
         * Default is /crypto/server.
         */
        private String basePath = "/crypto/server";
    }

    @Data
    public static class ExceptionHandlerProperties {
        /**
         * Whether to register the global CryptoExceptionHandler.
         * Default is true.
         */
        private boolean enabled = true;
    }
}
