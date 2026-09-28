package com.ikea.crypto.server.vault;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for HashiCorp Vault key synchronization.
 */
@Data
@Component
@ConfigurationProperties(prefix = "crypto.vault")
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
     * Vault KV v2 secret path (relative to /v1/), e.g. secret/data/crypto/pii-transport-key
     */
    private String secretPath = "secret/data/crypto/pii-transport-keys";

    /**
     * Logical key alias used in keyId format <keyAlias>:<version>.
     */
    private String keyAlias = "pii-transport-key";

    /**
     * Automatically bootstrap and initialize keys in Vault if none exist.
     */
    private boolean autoBootstrap = true;

    private long validityMillis = 365L * 24 * 60 * 60 * 1000; // 1 year
    private long gracePeriodMillis = 30L * 24 * 60 * 60 * 1000; // 30 days grace

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
