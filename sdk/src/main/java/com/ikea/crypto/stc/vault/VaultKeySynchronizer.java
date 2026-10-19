package com.ikea.crypto.stc.vault;

import com.ikea.crypto.stc.config.KeyLifecycleProperties;
import com.ikea.crypto.stc.config.SensitiveTransportCryptoProperties;
import com.ikea.crypto.stc.config.VaultProperties;
import com.ikea.crypto.stc.key.KeyRing;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.AllNestedConditions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Conditional;
import org.springframework.stereotype.Component;
import org.springframework.vault.core.VaultTemplate;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Synchronizes cryptographic keys from HashiCorp Vault into an in-memory KeyRing.
 * Eliminates disk dependencies across pods while keeping RSA decryption local and fast.
 */
@Slf4j
@Component
@Conditional(VaultKeySynchronizer.EnabledVaultCondition.class)
public class VaultKeySynchronizer {

    static class EnabledVaultCondition extends AllNestedConditions {
        EnabledVaultCondition() {
            super(ConfigurationPhase.REGISTER_BEAN);
        }

        @ConditionalOnProperty(prefix = "sensitive.transport.crypto", name = "enabled", havingValue = "true")
        static class CryptoEnabled {
        }

        @ConditionalOnProperty(prefix = "sensitive.transport.crypto", name = "key-store", havingValue = "vault", matchIfMissing = true)
        static class VaultKeyStore {
        }
    }

    private final VaultProperties properties;
    private final KeyLifecycleProperties lifecycleProperties;
    private final VaultClient vaultClient;

    public VaultKeySynchronizer(
            SensitiveTransportCryptoProperties cryptoProperties,
            VaultTemplate vaultTemplate
    ) {
        this.properties = cryptoProperties.getVault();
        this.lifecycleProperties = cryptoProperties.getKeyLifecycle();
        this.vaultClient = new VaultClient(vaultTemplate);
    }

    /**
     * Synchronizes RSA keys from Vault KV v2 into an in-memory KeyRing.
     *
     * @return Fully populated in-memory KeyRing
     */
    public KeyRing syncToKeyRing() throws GeneralSecurityException, IOException {
        VaultKeyRing vaultKeyRing = new VaultKeyRing(properties, lifecycleProperties, vaultClient, true);
        vaultKeyRing.initialize();
        return vaultKeyRing;
    }
}
