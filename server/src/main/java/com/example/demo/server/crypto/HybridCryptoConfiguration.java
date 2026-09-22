package com.example.demo.server.crypto;

import com.example.demo.crypto.EcdhHybridCryptoServer;
import com.example.demo.crypto.RsaHybridCryptoServer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

@Configuration
public class HybridCryptoConfiguration {
    @Bean
    public RsaHybridCryptoServer rsaHybridCryptoServer(
            @Value("${hybrid.crypto.key-directory:src/main/resources/keys}") String keyDirectory
    ) throws GeneralSecurityException, IOException {
        return RsaHybridCryptoServer.create(Path.of(keyDirectory));
    }

    @Bean
    public EcdhHybridCryptoServer ecdhHybridCryptoServer(
            @Value("${hybrid.crypto.key-directory:src/main/resources/keys}") String keyDirectory
    ) throws GeneralSecurityException, IOException {
        return EcdhHybridCryptoServer.create(Path.of(keyDirectory));
    }

    @Bean
    public RsaCryptoService rsaCryptoService(RsaHybridCryptoServer rsaHybridCryptoServer) {
        return new RsaCryptoService(rsaHybridCryptoServer);
    }

    @Bean
    public EcdhCryptoService ecdhCryptoService(EcdhHybridCryptoServer ecdhHybridCryptoServer) {
        return new EcdhCryptoService(ecdhHybridCryptoServer);
    }
}
