package com.example.demo.server.crypto.ecdh;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

@Configuration
public class EcdhCryptoConfiguration {

    @Bean
    public EcdhCryptoServer ecdhCryptoServer(
            @Value("${ecdh.crypto.key-directory:src/main/resources/keys}") String keyDirectory
    ) throws GeneralSecurityException, IOException {
        return EcdhCryptoServer.create(Path.of(keyDirectory));
    }

    public static boolean oneTimeUsedKey;

    @Value("${ecdh.crypto.one-time-used-key}")
    private boolean tmp;

    @PostConstruct
    public void init() {
        oneTimeUsedKey = tmp;
    }
}
