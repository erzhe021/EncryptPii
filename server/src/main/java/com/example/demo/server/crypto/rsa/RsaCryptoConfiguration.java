package com.example.demo.server.crypto.rsa;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

@Configuration
public class RsaCryptoConfiguration {
    @Bean
    public RsaCryptoServer rsaCryptoServer(
            @Value("${rsa.crypto.key-directory:src/main/resources/keys}") String keyDirectory
    ) throws GeneralSecurityException, IOException {
        return RsaCryptoServer.create(Path.of(keyDirectory));
    }

}
