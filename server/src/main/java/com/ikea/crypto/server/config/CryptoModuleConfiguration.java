package com.ikea.crypto.server.config;

import com.ikea.crypto.server.codec.ecdh.EcdhCryptoPayloadHandler;
import com.ikea.crypto.server.service.EcdhCryptoServer;
import com.ikea.crypto.server.codec.rsa.RsaCryptoPayloadHandler;
import com.ikea.crypto.server.service.RsaCryptoServer;
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
