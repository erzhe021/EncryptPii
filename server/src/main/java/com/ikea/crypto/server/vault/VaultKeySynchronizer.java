package com.ikea.crypto.server.vault;

import com.ikea.crypto.server.service.KeyRing;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

/**
 * Synchronizes cryptographic keys from HashiCorp Vault into an in-memory KeyRing.
 * Eliminates disk dependencies across pods while keeping RSA decryption local and fast.
 */
@Slf4j
@Component
public class VaultKeySynchronizer {

    private final VaultProperties properties;
    private final VaultClient vaultClient;

    @Autowired
    public VaultKeySynchronizer(VaultProperties properties) {
        this.properties = properties;
        this.vaultClient = new VaultClient(properties.getAddr());
    }

    public VaultKeySynchronizer(VaultProperties properties, VaultClient vaultClient) {
        this.properties = properties;
        this.vaultClient = vaultClient;
    }

    /**
     * Authenticates with Vault using the configured authentication method and retrieves a Vault token.
     */
    public String authenticate() throws IOException, InterruptedException {
        if (properties.getAuthMethod() == VaultProperties.AuthMethod.KUBERNETES) {
            String jwt = resolveKubernetesJwt();
            String role = properties.getKubernetes().getRole();
            log.info("Authenticating to Vault using Kubernetes auth method, role='{}'", role);
            return vaultClient.loginWithKubernetes(role, jwt);
        } else {
            log.info("Using configured Vault token for authentication");
            return properties.getToken();
        }
    }

    /**
     * Synchronizes RSA keys from Vault KV v2 into an in-memory KeyRing.
     *
     * @return Fully populated in-memory KeyRing
     */
    public KeyRing syncToKeyRing() throws GeneralSecurityException, IOException, InterruptedException {
        VaultKeyRing vaultKeyRing = new VaultKeyRing(properties, vaultClient);
        vaultKeyRing.initialize();
        return vaultKeyRing;
    }

    private String resolveKubernetesJwt() throws IOException {
        // If explicit JWT is provided in properties, use it
        if (properties.getKubernetes().getJwt() != null && !properties.getKubernetes().getJwt().isBlank()) {
            return properties.getKubernetes().getJwt().trim();
        }

        // Otherwise read from mounted ServiceAccount token file
        Path tokenFile = Path.of(properties.getKubernetes().getTokenPath());
        if (Files.exists(tokenFile)) {
            return Files.readString(tokenFile).trim();
        }

        throw new IllegalStateException("Kubernetes ServiceAccount token file not found at " + tokenFile
                + ", and no explicit jwt was configured.");
    }
}
