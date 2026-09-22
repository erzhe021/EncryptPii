package com.example.demo.server.crypto;

import com.example.demo.crypto.HybridCryptoServer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

/**
 * Configuration class for setting up the HybridCryptoServer bean.
 * This class is responsible for initializing the cryptographic server with the specified key directory.
 */
@Configuration
public class HybridCryptoConfiguration {
    /**
     * Creates and configures a HybridCryptoServer bean.
     *
     * @param keyDirectory the directory where cryptographic keys are stored, defaulting to "server/src/main/resources/keys"
     * @return an instance of HybridCryptoServer
     * @throws GeneralSecurityException if there is a security-related issue during initialization
     * @throws IOException              if there is an I/O error while accessing the key directory
     */
    @Bean
    public HybridCryptoServer hybridCryptoServer(
            @Value("${hybrid.crypto.key-directory:server/src/main/resources/keys}") String keyDirectory
    ) throws GeneralSecurityException, IOException {
        return HybridCryptoServer.create(Path.of(keyDirectory));
    }
}
