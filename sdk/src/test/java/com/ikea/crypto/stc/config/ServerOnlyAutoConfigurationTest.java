package com.ikea.crypto.stc.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.web.advice.RequestDecryptAdvice;
import com.ikea.crypto.stc.web.advice.ResponseEncryptAdvice;
import com.ikea.crypto.stc.web.codec.CryptoPayloadHandler;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class ServerOnlyAutoConfigurationTest {

    private final WebApplicationContextRunner webRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SensitiveTransportCryptoAutoConfiguration.class))
            .withBean(ObjectMapper.class, ObjectMapper::new)
            .withPropertyValues("sensitive.transport.crypto.vault.enabled=false");

    @Test
    void servletApplicationReceivesServerComponents() {
        webRunner.run(context -> {
            assertThat(context).hasNotFailed()
                    .hasSingleBean(CryptoServer.class)
                    .hasSingleBean(CryptoPayloadHandler.class)
                    .hasSingleBean(RequestDecryptAdvice.class)
                    .hasSingleBean(ResponseEncryptAdvice.class);
        });
    }

    @Test
    void sdkCanBeDisabledForServletApplication() {
        webRunner.withPropertyValues("sensitive.transport.crypto.enabled=false").run(context -> {
            assertThat(context).hasNotFailed()
                    .doesNotHaveBean(CryptoServer.class)
                    .doesNotHaveBean(CryptoPayloadHandler.class);
        });
    }

    @Test
    void nonWebApplicationDoesNotReceiveServerComponents() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(SensitiveTransportCryptoAutoConfiguration.class))
                .run(context -> assertThat(context).hasNotFailed()
                        .doesNotHaveBean(CryptoServer.class)
                        .doesNotHaveBean(RequestDecryptAdvice.class)
                        .doesNotHaveBean(ResponseEncryptAdvice.class));
    }
}
