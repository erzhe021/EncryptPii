package com.ikea.crypto.client.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.client.core.CryptoClient;
import com.ikea.crypto.client.core.CryptoHttpClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.URI;

@Configuration
public class CryptoClientConfiguration {

    @Bean
    public CryptoClient cryptoClient() {
        return new CryptoClient();
    }

    @Bean
    public CryptoHttpClient cryptoHttpClient(
            @Value("${crypto.server.base-url:http://localhost:9090}") String serverBaseUrl,
            @Value("${crypto.server.endpoints.ecdh.ephemeral-public-key:/crypto/server/ecdh/ephemeral-public-key}") String ecdhEphemeralPublicKeyPath,
            @Value("${crypto.server.endpoints.ecdh.ecdsa-public-key:/crypto/server/ecdh/ecdsa-public-key}") String ecdsaPublicKeyPath,
            ObjectMapper objectMapper
    ) {
        return new CryptoHttpClient(
                URI.create(serverBaseUrl),
                ecdhEphemeralPublicKeyPath,
                ecdsaPublicKeyPath,
                objectMapper != null ? objectMapper : new ObjectMapper()
        );
    }
}
