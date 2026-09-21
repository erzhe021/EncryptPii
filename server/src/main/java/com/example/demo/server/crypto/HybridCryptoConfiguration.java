package com.example.demo.server.crypto;

import com.example.demo.crypto.HybridCryptoServer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

@Configuration
public class HybridCryptoConfiguration {
    @Bean
    public HybridCryptoServer hybridCryptoServer(
            @Value("${hybrid.crypto.key-directory:server/src/main/resources/rsa-keys}") String keyDirectory
    ) throws GeneralSecurityException, IOException {
        return HybridCryptoServer.create(Path.of(keyDirectory));
    }
}
