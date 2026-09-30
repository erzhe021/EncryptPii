package com.ikea.crypto.stc.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for Vault integration in sensitive transport crypto functionality.
 * <p>
 * These properties can be set in the application's configuration files (e.g., application.properties or application.yml)
 * to customize the behavior of Vault integration for key management and retrieval.
 * </p>
 */
@Data
@ConfigurationProperties(prefix = "sensitive.transport.crypto.vault")
public class VaultProperties {

    /**
     * Whether Vault key management is enabled. Defaults to false.
     */
    private boolean enabled = false;

    /**
     * Vault server base URL, e.g. http://127.0.0.1:8200
     */
    private String addr = "http://127.0.0.1:8200";

    /**
     * Authentication method: KUBERNETES or TOKEN.
     */
    private AuthMethod authMethod = AuthMethod.TOKEN;

    /**
     * Vault static token (used when authMethod is TOKEN, or for local dev/testing).
     */
    private String token = "root";

    /**
     * Authentication mount path, e.g. auth/kubernetes or auth/token.
     */
    private String authPath = "auth/kubernetes";

    /**
     * Vault KV v2 secret path (relative to /v1/), e.g. secret/data/sensitive-transport-crypto/ciam
     */
    private String secretPath = "secret/data/sensitive-transport-crypto/ciam";

    /**
     * Logical key alias used in keyId format <keyAlias>:<version>.
     */
    private String keyAlias = "ciam";

    /**
     * Automatically bootstrap and initialize keys in Vault if none exist.
     */
    private boolean autoBootstrap = true;

    /**
     * Key validity duration in milliseconds before rotation is required.
     * Default: 1 year (365 days).
     */
    private long validityMillis = 365L * 24 * 60 * 60 * 1000;

    /**
     * Grace period in milliseconds after key expiration during which old keys are still accepted for decryption.
     * Default: 30 days.
     */
    private long gracePeriodMillis = 30L * 24 * 60 * 60 * 1000;

    /**
     * Wait time in milliseconds for pods that lost CAS competition before re-fetching the updated key from Vault.
     * Default: 1200ms (1~2 seconds).
     */
    private long casBackoffMillis = 1200L;

    /**
     * Maximum number of attempts to poll Vault after CAS competition loss.
     */
    private int casMaxRetries = 3;

    /**
     * Interval in milliseconds between retries when polling Vault after CAS conflict.
     */
    private long casRetryIntervalMillis = 500L;

    /**
     * Kubernetes authentication properties.
     */
    private KubernetesProperties kubernetes = new KubernetesProperties();

    public enum AuthMethod {
        TOKEN,
        KUBERNETES
    }

    @Data
    public static class KubernetesProperties {
        /**
         * Vault role configured in Vault's kubernetes auth engine.
         */
        private String role = "crypto-server";

        /**
         * Path to the service account token mounted by Kubernetes.
         */
        private String tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token";

        /**
         * Direct ServiceAccount JWT string (useful for local simulation or overriding).
         */
        private String jwt;
    }
}
