package com.ikea.crypto.server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.config.SensitiveTransportCryptoAutoConfiguration;
import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.web.advice.RequestDecryptAdvice;
import com.ikea.crypto.stc.web.advice.ResponseEncryptAdvice;
import com.ikea.crypto.stc.web.codec.CryptoPayloadHandler;
import com.ikea.crypto.stc.web.endpoint.CryptoKeyEndpoint;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static org.assertj.core.api.Assertions.assertThat;

class SensitiveTransportCryptoAutoConfigurationTest {

    @Configuration
    static class ObjectMapperTestConfig {
        @Bean
        ObjectMapper objectMapper() {
            return new ObjectMapper();
        }
    }

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withUserConfiguration(ObjectMapperTestConfig.class)
            .withConfiguration(AutoConfigurations.of(SensitiveTransportCryptoAutoConfiguration.class));

    @Test
    void defaultConfigurationLoadsAllBeansWithInMemoryFallback() {
        contextRunner.withPropertyValues("sensitive.transport.crypto.enabled=true")
                .run(context -> {
                    assertThat(context).hasSingleBean(CryptoServer.class);
                    assertThat(context).hasSingleBean(CryptoPayloadHandler.class);
                    assertThat(context).hasSingleBean(RequestDecryptAdvice.class);
                    assertThat(context).hasSingleBean(ResponseEncryptAdvice.class);
                    assertThat(context.getBeansWithAnnotation(RestControllerAdvice.class)).isEmpty();
                    assertThat(context).hasSingleBean(CryptoKeyEndpoint.class);

                    CryptoServer cryptoServer = context.getBean(CryptoServer.class);
                    assertThat(cryptoServer.getPublicKey()).isNotNull();
                    assertThat(cryptoServer.getPublicKey().publicKeyBase64()).isNotBlank();
                });
    }

    @Test
    void disabledConfigurationLoadsNoBeans() {
        contextRunner.withPropertyValues("sensitive.transport.crypto.enabled=false")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(CryptoServer.class);
                    assertThat(context).doesNotHaveBean(CryptoPayloadHandler.class);
                    assertThat(context).doesNotHaveBean(RequestDecryptAdvice.class);
                    assertThat(context).doesNotHaveBean(ResponseEncryptAdvice.class);
                    assertThat(context).doesNotHaveBean(CryptoKeyEndpoint.class);
                });
    }

    @Test
    void disableEndpointOnly() {
        contextRunner
                .withPropertyValues("sensitive.transport.crypto.enabled=true")
                .withPropertyValues("sensitive.transport.crypto.endpoint.enabled=false")
                .run(context -> {
                    assertThat(context).hasSingleBean(CryptoServer.class);
                    assertThat(context).doesNotHaveBean(CryptoKeyEndpoint.class);
                });
    }

}
