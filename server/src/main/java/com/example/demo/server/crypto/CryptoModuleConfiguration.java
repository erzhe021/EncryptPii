package com.example.demo.server.crypto;

import com.example.demo.server.crypto.ecdh.EcdhCryptoPayloadHandler;
import com.example.demo.server.crypto.ecdh.EcdhCryptoServer;
import com.example.demo.server.crypto.rsa.RsaCryptoPayloadHandler;
import com.example.demo.server.crypto.rsa.RsaCryptoServer;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CryptoModuleConfiguration {

    @Bean
    public RsaCryptoPayloadHandler rsaCryptoPayloadHandler(RsaCryptoServer rsaCryptoServer, ObjectMapper objectMapper) {
        return new RsaCryptoPayloadHandler(rsaCryptoServer, objectMapper);
    }

    @Bean
    public EcdhCryptoPayloadHandler ecdhCryptoPayloadHandler(EcdhCryptoServer ecdhCryptoServer, ObjectMapper objectMapper) {
        return new EcdhCryptoPayloadHandler(ecdhCryptoServer, objectMapper);
    }
}
