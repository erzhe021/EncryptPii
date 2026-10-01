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
     * Whether Vault key management is enabled. Defaults to true for the managed-key setup.
     */
    private boolean enabled = true;

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
     * Vault KV v2 secret path for the ECDSA key material.
     */
    private String ecdsaSecretPath = "secret/data/sensitive-transport-crypto/ecdsa-ciam";

    /**
     * Vault KV v2 secret path for the AES ticket master key.
     */
    private String aesSecretPath = "secret/data/sensitive-transport-crypto/aes-ciam";

    /**
     * Backward compatible alias for the ECDSA secret path.
     */
    private String secretPath = ecdsaSecretPath;

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
     * Default: 60 seconds for local testing, increase in production.
     */
    private long validityMillis = 60_000L;

    /**
     * Grace period in milliseconds after key expiration during which old keys are still accepted for decryption.
     * Default: 30 seconds for local testing.
     */
    private long gracePeriodMillis = 30_000L;

    /**
     * Whether auto-rotation should be enabled for both ECDSA and AES secrets.
     */
    private boolean autoRotate = true;

    /**
     * How often the in-memory crypto server checks Vault for expired keys and rotates them.
     */
    private long rotationCheckIntervalMillis = 10_000L;

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
