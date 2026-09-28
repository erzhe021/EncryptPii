package com.ikea.crypto.server.config;

import com.ikea.crypto.server.service.CryptoServer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

@Configuration
public class CryptoConfiguration {
    @Bean
    public CryptoServer cryptoServer(
            @Value("${crypto.key.directory:src/main/resources/keys}") String keyDirectory
    ) throws GeneralSecurityException, IOException {
        Path path = Path.of(keyDirectory);
        if (!java.nio.file.Files.exists(path)) {
            Path fallback = Path.of("src/main/resources/keys");
            if (java.nio.file.Files.exists(fallback)) {
                path = fallback;
            }
        }
        return CryptoServer.create(path);
    }

}
