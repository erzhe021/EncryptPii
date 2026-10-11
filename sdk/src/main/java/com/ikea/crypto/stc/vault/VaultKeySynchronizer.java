package com.ikea.crypto.stc.vault;

import com.ikea.crypto.stc.config.KeyLifecycleProperties;
import com.ikea.crypto.stc.config.VaultProperties;
import com.ikea.crypto.stc.key.KeyRing;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Synchronizes cryptographic keys from HashiCorp Vault into an in-memory KeyRing.
 * Eliminates disk dependencies across pods while keeping RSA decryption local and fast.
 */
@Slf4j
@Component
public class VaultKeySynchronizer {

    private final VaultProperties properties;
    private final KeyLifecycleProperties lifecycleProperties;
    private final VaultClient vaultClient;

    @Autowired
    public VaultKeySynchronizer(VaultProperties properties, KeyLifecycleProperties lifecycleProperties) {
        this(properties, lifecycleProperties, new VaultClient(properties.getAddr()));
    }

    public VaultKeySynchronizer(
            VaultProperties properties,
            KeyLifecycleProperties lifecycleProperties,
            VaultClient vaultClient
    ) {
        this.properties = properties;
        this.lifecycleProperties = lifecycleProperties;
        this.vaultClient = vaultClient;
    }

    /**
     * Synchronizes RSA keys from Vault KV v2 into an in-memory KeyRing.
     *
     * @return Fully populated in-memory KeyRing
     */
    public KeyRing syncToKeyRing() throws GeneralSecurityException, IOException {
        VaultKeyRing vaultKeyRing = new VaultKeyRing(
                properties, lifecycleProperties, vaultClient, true);
        vaultKeyRing.initialize();
        return vaultKeyRing;
    }
}
