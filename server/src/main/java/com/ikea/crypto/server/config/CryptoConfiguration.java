package com.ikea.crypto.server.config;

import com.ikea.crypto.server.service.CryptoServer;
import com.ikea.crypto.server.vault.VaultClient;
import com.ikea.crypto.server.vault.VaultKeyRing;
import com.ikea.crypto.server.vault.VaultProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.security.GeneralSecurityException;

@Slf4j
@Configuration
public class CryptoConfiguration {

    @Bean
    public CryptoServer cryptoServer(VaultProperties vaultProperties) throws GeneralSecurityException, IOException {
        log.info("Vault key management enabled. Loading and managing keys via Vault at {}", vaultProperties.getAddr());
        VaultClient vaultClient = new VaultClient(vaultProperties.getAddr());
        VaultKeyRing vaultKeyRing = new VaultKeyRing(vaultProperties, vaultClient);
        vaultKeyRing.initialize();
        return new CryptoServer(vaultKeyRing);
    }

}
