package com.ikea.crypto.server.config;

import com.ikea.crypto.server.service.CryptoServer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

@Configuration
public class CryptoConfiguration {

    @Bean
    public CryptoServer ecdhCryptoServer(
            @Value("${crypto.key.directory:src/main/resources/keys}") String keyDirectory
    ) throws GeneralSecurityException, IOException {
        Path path = resolveKeyDirectory(keyDirectory);
        return CryptoServer.create(path);
    }

    private Path resolveKeyDirectory(String keyDirectory) {
        if (keyDirectory != null && !keyDirectory.isBlank()) {
            Path configured = Path.of(keyDirectory);
            if (Files.exists(configured.resolve("ecdsa-private-key.pkcs8"))) {
                return configured;
            }
            if (keyDirectory.contains("/server/src/main/resources/keys")) {
                Path candidate = Path.of(keyDirectory.replace("/server/src/main/resources/keys", "/src/main/resources/keys"));
                if (Files.exists(candidate.resolve("ecdsa-private-key.pkcs8"))) {
                    return candidate;
                }
            }
            if (Files.exists(configured)) {
                return configured;
            }
        }
        Path localKeys = Path.of("src/main/resources/keys");
        if (Files.exists(localKeys.resolve("ecdsa-private-key.pkcs8"))) {
            return localKeys;
        }
        Path rootKeys = Path.of("server/src/main/resources/keys");
        if (Files.exists(rootKeys.resolve("ecdsa-private-key.pkcs8"))) {
            return rootKeys;
        }
        return localKeys;
    }
}
