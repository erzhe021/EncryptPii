package com.ikea.crypto.server.config;

import com.ikea.crypto.server.service.EcdhCryptoServer;
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
}
