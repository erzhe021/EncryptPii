package com.ikea.crypto.server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.server.advice.RequestDecryptAdvice;
import com.ikea.crypto.server.advice.ResponseEncryptAdvice;
import com.ikea.crypto.server.codec.CryptoPayloadHandler;
import com.ikea.crypto.server.endpoint.CryptoKeyEndpoint;
import com.ikea.crypto.server.error.CryptoExceptionHandler;
import com.ikea.crypto.server.service.CryptoServer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

class CryptoServerAutoConfigurationTest {

    @Configuration
    static class ObjectMapperTestConfig {
        @Bean
        ObjectMapper objectMapper() {
            return new ObjectMapper();
        }
    }

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withUserConfiguration(ObjectMapperTestConfig.class)
            .withConfiguration(AutoConfigurations.of(CryptoServerAutoConfiguration.class));

    @Test
    void defaultConfigurationLoadsAllBeansWithInMemoryFallback() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(CryptoServer.class);
            assertThat(context).hasSingleBean(CryptoPayloadHandler.class);
            assertThat(context).hasSingleBean(RequestDecryptAdvice.class);
            assertThat(context).hasSingleBean(ResponseEncryptAdvice.class);
            assertThat(context).hasSingleBean(CryptoExceptionHandler.class);
            assertThat(context).hasSingleBean(CryptoKeyEndpoint.class);

            CryptoServer cryptoServer = context.getBean(CryptoServer.class);
            assertThat(cryptoServer.getPublicKey()).isNotNull();
            assertThat(cryptoServer.getPublicKey().publicKeyBase64()).isNotBlank();
        });
    }

    @Test
    void disabledConfigurationLoadsNoBeans() {
        contextRunner.withPropertyValues("crypto.server.enabled=false")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(CryptoServer.class);
                    assertThat(context).doesNotHaveBean(CryptoPayloadHandler.class);
                    assertThat(context).doesNotHaveBean(RequestDecryptAdvice.class);
                    assertThat(context).doesNotHaveBean(ResponseEncryptAdvice.class);
                    assertThat(context).doesNotHaveBean(CryptoExceptionHandler.class);
                    assertThat(context).doesNotHaveBean(CryptoKeyEndpoint.class);
                });
    }

    @Test
    void disableEndpointOnly() {
        contextRunner.withPropertyValues("crypto.server.endpoint.enabled=false")
                .run(context -> {
                    assertThat(context).hasSingleBean(CryptoServer.class);
                    assertThat(context).doesNotHaveBean(CryptoKeyEndpoint.class);
                });
    }

    @Test
    void disableExceptionHandlerOnly() {
        contextRunner.withPropertyValues("crypto.server.exception-handler.enabled=false")
                .run(context -> {
                    assertThat(context).hasSingleBean(CryptoServer.class);
                    assertThat(context).doesNotHaveBean(CryptoExceptionHandler.class);
                });
    }
}
