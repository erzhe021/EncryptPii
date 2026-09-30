package com.ikea.crypto.stc.vault;

import com.ikea.crypto.stc.config.VaultProperties;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Handles Vault authentication for Kubernetes SA tokens and static tokens.
 */
@Slf4j
public class VaultAuthenticator {

    private final VaultProperties properties;
    private final VaultClient vaultClient;
    private volatile String cachedToken;

    public VaultAuthenticator(VaultProperties properties, VaultClient vaultClient) {
        this.properties = properties;
        this.vaultClient = vaultClient;
    }

    /**
     * Authenticates with Vault using the configured authentication method and retrieves a Vault token.
     * Caches the authenticated token to avoid redundant login handshakes and duplicate logging.
     */
    public String authenticate() throws IOException, InterruptedException {
        if (cachedToken != null && !cachedToken.isBlank()) {
            return cachedToken;
        }
        synchronized (this) {
            if (cachedToken != null && !cachedToken.isBlank()) {
                return cachedToken;
            }
            if (properties.getAuthMethod() == VaultProperties.AuthMethod.KUBERNETES) {
                String jwt = resolveKubernetesJwt();
                String role = properties.getKubernetes().getRole();
                log.info("Authenticating to Vault via Kubernetes Auth (role: '{}')", role);
                this.cachedToken = vaultClient.loginWithKubernetes(properties.getAuthPath(), role, jwt);
            } else {
                log.debug("Using configured Vault static token for authentication");
                this.cachedToken = properties.getToken();
            }
            return this.cachedToken;
        }
    }

    /**
     * Invalidates the cached Vault token so the next call performs a fresh login.
     */
    public synchronized void invalidateToken() {
        this.cachedToken = null;
    }

    private String resolveKubernetesJwt() throws IOException {
        if (properties.getKubernetes().getJwt() != null && !properties.getKubernetes().getJwt().isBlank()) {
            return properties.getKubernetes().getJwt().trim();
        }

        Path tokenFile = Path.of(properties.getKubernetes().getTokenPath());
        if (Files.exists(tokenFile)) {
            return Files.readString(tokenFile).trim();
        }

        throw new IllegalStateException("Kubernetes ServiceAccount token file not found at " + tokenFile
                + ", and no explicit jwt was configured.");
    }
}
