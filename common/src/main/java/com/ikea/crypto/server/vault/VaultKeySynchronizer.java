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
    private final VaultAuthenticator authenticator;

    @Autowired
    public VaultKeySynchronizer(VaultProperties properties) {
        this(properties, new VaultClient(properties.getAddr()));
    }

    public VaultKeySynchronizer(VaultProperties properties, VaultClient vaultClient) {
        this.properties = properties;
        this.vaultClient = vaultClient;
        this.authenticator = new VaultAuthenticator(properties, vaultClient);
    }

    /**
     * Authenticates with Vault using the configured authentication method and retrieves a Vault token.
     */
    public String authenticate() throws IOException, InterruptedException {
        return authenticator.authenticate();
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
}
