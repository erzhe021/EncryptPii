package com.example.demo.server.crypto;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class CryptoAdviceConfiguration {
    @Bean
    public CryptoPayloadHandlerRegistry cryptoPayloadHandlerRegistry(List<CryptoPayloadHandler> handlers) {
        return new CryptoPayloadHandlerRegistry(handlers);
    }
}
