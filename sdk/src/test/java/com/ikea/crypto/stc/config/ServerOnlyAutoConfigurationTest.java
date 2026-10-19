package com.ikea.crypto.stc.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.key.KeyRing;
import com.ikea.crypto.stc.model.KeyMetadata;
import com.ikea.crypto.stc.vault.VaultKeyCodec;
import com.ikea.crypto.stc.vault.VaultKeyRing;
import com.ikea.crypto.stc.vault.VaultKeySynchronizer;
import com.ikea.crypto.stc.web.advice.RequestDecryptAdvice;
import com.ikea.crypto.stc.web.advice.ResponseEncryptAdvice;
import com.ikea.crypto.stc.web.codec.CryptoPayloadHandler;
import com.ikea.crypto.stc.web.endpoint.PublicKeyEndpoint;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.VaultVersionedKeyValueOperations;
import org.springframework.vault.support.Versioned;

import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class ServerOnlyAutoConfigurationTest {

    private final WebApplicationContextRunner webRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SensitiveTransportCryptoAutoConfiguration.class))
            .withBean(ObjectMapper.class, ObjectMapper::new)
            .withPropertyValues(
                    "sensitive.transport.crypto.enabled=true",
                    "sensitive.transport.crypto.vault.secret-path=secret/data/test-service",
                    "sensitive.transport.crypto.vault.key-alias=test-service",
                    "sensitive.transport.crypto.key-lifecycle.validity-millis=120000",
                    "sensitive.transport.crypto.key-lifecycle.rotation-before-expiry-millis=20000",
                    "sensitive.transport.crypto.key-lifecycle.grace-period-millis=10000");

    @Test
    void servletApplicationReceivesServerComponents() throws Exception {
        VaultTemplate template = mock(VaultTemplate.class);
        VaultVersionedKeyValueOperations operations = mock(VaultVersionedKeyValueOperations.class);
        Versioned.Metadata metadata = mock(Versioned.Metadata.class);
        when(metadata.getVersion()).thenReturn(Versioned.Version.from(1));
        when(metadata.getCreatedAt()).thenReturn(Instant.now());
        Map<String, Object> keyData = new VaultKeyCodec().serializeKeyPair(
                KeyPairGenerator.getInstance("RSA").generateKeyPair());
        Versioned<Map<String, Object>> secret = Versioned.create(keyData, metadata);
        when(template.opsForVersionedKeyValue("secret")).thenReturn(operations);
        when(operations.get("test-service")).thenReturn(secret);
        webRunner.withBean(VaultTemplate.class, () -> template).run(context -> {
            assertThat(context).hasNotFailed()
                    .hasSingleBean(CryptoServer.class)
                    .hasSingleBean(CryptoPayloadHandler.class)
                    .hasSingleBean(RequestDecryptAdvice.class)
                    .hasSingleBean(ResponseEncryptAdvice.class)
                    .hasSingleBean(SensitiveTransportCryptoProperties.class)
                    .doesNotHaveBean(KeyLifecycleProperties.class)
                    .doesNotHaveBean(VaultProperties.class)
                    .satisfies(applicationContext -> {
                        SensitiveTransportCryptoProperties properties =
                                applicationContext.getBean(SensitiveTransportCryptoProperties.class);
                        assertThat(properties.getVault().getKeyAlias()).isEqualTo("test-service");
                        assertThat(properties.getKeyLifecycle().getValidityMillis()).isEqualTo(120000);
                        assertThat(properties.getKeyStore()).isEqualTo(SensitiveTransportCryptoProperties.KeyStore.VAULT);
                        assertThat(applicationContext.getBean(CryptoServer.class).keyRing())
                                .isInstanceOf(VaultKeyRing.class);
                        assertThat(applicationContext.getBean(CryptoServer.class).getPublicKey().keyId())
                                .isEqualTo("test-service:1");
                    });
        });
    }

    @Test
    void missingVaultTemplateFailsWithConfigurationError() {
        webRunner.run(context -> assertThat(context).hasFailed().getFailure()
                .hasRootCauseMessage("VaultTemplate is required: enable and configure Spring Cloud Vault"));
    }

    @Test
    void missingVaultPathFailsWithConfigurationError() {
        webRunner.withPropertyValues("sensitive.transport.crypto.vault.secret-path=").run(context ->
                assertThat(context).hasFailed().getFailure()
                        .hasRootCauseMessage("sensitive.transport.crypto.vault.secret-path must be configured"));
    }

    @Test
    void missingVaultAliasFailsWithConfigurationError() {
        webRunner.withPropertyValues("sensitive.transport.crypto.vault.key-alias=").run(context ->
                assertThat(context).hasFailed().getFailure()
                        .hasRootCauseMessage("sensitive.transport.crypto.vault.key-alias must be configured"));
    }

    @Test
    void vaultReadFailurePropagatesWithoutMemoryFallback() {
        VaultTemplate template = mock(VaultTemplate.class);
        when(template.opsForVersionedKeyValue("secret"))
                .thenThrow(new IllegalStateException("Vault unavailable"));
        webRunner.withBean(VaultTemplate.class, () -> template).run(context ->
                assertThat(context).hasFailed().getFailure().hasRootCauseMessage("Vault unavailable"));
    }

    @Test
    void missingKeysFailWhenBootstrapIsDisabled() {
        VaultTemplate template = mock(VaultTemplate.class);
        when(template.opsForVersionedKeyValue("secret"))
                .thenReturn(mock(VaultVersionedKeyValueOperations.class));
        webRunner.withBean(VaultTemplate.class, () -> template)
                .withPropertyValues("sensitive.transport.crypto.vault.auto-bootstrap=false")
                .run(context -> assertThat(context).hasFailed().getFailure()
                        .hasRootCauseMessage("No RSA keys found in Vault at path: secret/data/test-service"));
    }

    @Test
    void explicitMemoryModeDoesNotAccessVault() {
        VaultTemplate template = mock(VaultTemplate.class);
        webRunner.withBean(VaultTemplate.class, () -> template)
                .withPropertyValues("sensitive.transport.crypto.key-store=memory")
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(CryptoServer.class);
                    assertThat(context.getBean(CryptoServer.class).keyRing()).isExactlyInstanceOf(KeyRing.class);
                    assertThat(context.getBean(CryptoServer.class).keyRing().getKeyAlias())
                            .isEqualTo("in-memory-test-key");
                    verify(template).afterPropertiesSet();
                    verifyNoMoreInteractions(template);
                });
    }

    @Test
    void memoryModeDoesNotCreateVaultSynchronizerEvenWhenComponentScanned() {
        webRunner.withUserConfiguration(VaultKeySynchronizer.class)
                .withPropertyValues("sensitive.transport.crypto.key-store=memory")
                .run(context -> assertThat(context).hasNotFailed()
                        .hasSingleBean(CryptoServer.class)
                        .doesNotHaveBean(VaultKeySynchronizer.class));
    }

    @Test
    void enabledVaultModeRetainsComponentScannedSynchronizer() {
        CryptoServer testServer = new CryptoServer(new KeyRing("test-service", 120000, 10000, false, 20000));
        webRunner.withUserConfiguration(VaultKeySynchronizer.class)
                .withBean(CryptoServer.class, () -> testServer)
                .withBean(VaultTemplate.class, () -> mock(VaultTemplate.class))
                .run(context -> assertThat(context).hasNotFailed()
                        .hasSingleBean(VaultKeySynchronizer.class));
    }

    @Test
    void memoryAliasIsStableAcrossContextsButKeyIdsAndKeysChange() {
        AtomicReference<String> firstKeyId = new AtomicReference<>();
        AtomicReference<String> firstPublicKey = new AtomicReference<>();
        WebApplicationContextRunner memoryRunner = webRunner.withPropertyValues(
                "sensitive.transport.crypto.key-store=memory",
                "sensitive.transport.crypto.memory.key-alias=local-service");
        memoryRunner.run(context -> {
            assertThat(context).hasNotFailed();
            var publicKey = context.getBean(CryptoServer.class).getPublicKey("local-service");
            firstKeyId.set(publicKey.keyId());
            firstPublicKey.set(publicKey.publicKeyBase64());
        });
        memoryRunner.run(context -> {
            assertThat(context).hasNotFailed();
            CryptoServer server = context.getBean(CryptoServer.class);
            var publicKey = server.getPublicKey("local-service");
            assertThat(publicKey.keyId()).startsWith("local-service:").isNotEqualTo(firstKeyId.get());
            assertThat(publicKey.publicKeyBase64()).isNotEqualTo(firstPublicKey.get());
            long version = new KeyMetadata(publicKey.keyId(), 0, 0).version();
            assertThat(version).isBetween(1L, (1L << 52) - 1);
            assertThat(server.rotateKey("local-service").keyId()).isEqualTo("local-service:" + (version + 1));
            assertThat(server.keyRing().findKeyEntry(publicKey.keyId())).isPresent();
        });
    }

    @Test
    void invalidMemoryAliasFails() {
        webRunner.withPropertyValues(
                "sensitive.transport.crypto.key-store=memory",
                "sensitive.transport.crypto.memory.key-alias=").run(context ->
                assertThat(context).hasFailed().getFailure()
                        .hasRootCauseMessage("sensitive.transport.crypto.memory.key-alias must not be blank"));
        webRunner.withPropertyValues(
                "sensitive.transport.crypto.key-store=memory",
                "sensitive.transport.crypto.memory.key-alias=invalid:alias").run(context ->
                assertThat(context).hasFailed().getFailure()
                        .hasRootCauseMessage("sensitive.transport.crypto.memory.key-alias must not contain ':'"));
    }

    @Test
    void unknownKeyStoreFailsInsteadOfFallingBack() {
        webRunner.withPropertyValues("sensitive.transport.crypto.key-store=unknown").run(context ->
                assertThat(context).hasFailed());
    }

    @Test
    void explicitlyProvidedTestServerOverridesDefaultVaultConfiguration() {
        CryptoServer testServer = new CryptoServer(new KeyRing("test-service", 120000, 10000, false, 20000));
        webRunner.withBean(CryptoServer.class, () -> testServer).run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(CryptoServer.class);
            assertThat(context.getBean(CryptoServer.class)).isSameAs(testServer);
        });
    }

    @Test
    void publicKeyEndpointIsEnabledByDefault() {
        webRunner.withPropertyValues("sensitive.transport.crypto.key-store=memory")
                .run(context -> assertThat(context).hasNotFailed().hasSingleBean(PublicKeyEndpoint.class));
    }

    @Test
    void disablingEndpointRetainsCryptoComponents() {
        webRunner.withPropertyValues(
                "sensitive.transport.crypto.key-store=memory",
                "sensitive.transport.crypto.endpoint.enabled=false",
                "sensitive.transport.crypto.auto-rotate=false").run(context -> {
            assertThat(context).hasNotFailed()
                    .hasSingleBean(CryptoServer.class)
                    .hasSingleBean(RequestDecryptAdvice.class)
                    .hasSingleBean(ResponseEncryptAdvice.class)
                    .doesNotHaveBean(PublicKeyEndpoint.class);
            assertThat(context.getBean(CryptoServer.class).keyRing().isAutoRotate()).isFalse();
        });
    }

    @Test
    void sdkCanBeDisabledForServletApplication() {
        webRunner.withPropertyValues("sensitive.transport.crypto.enabled=false").run(context -> {
            assertThat(context).hasNotFailed()
                    .doesNotHaveBean(CryptoServer.class)
                    .doesNotHaveBean(CryptoPayloadHandler.class)
                    .doesNotHaveBean(RequestDecryptAdvice.class)
                    .doesNotHaveBean(ResponseEncryptAdvice.class)
                    .doesNotHaveBean(PublicKeyEndpoint.class);
        });
    }

    @Test
    void omittedServerSwitchDefaultsToDisabledWithoutVault() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        SensitiveTransportCryptoAutoConfiguration.class, CryptoProtocolAutoConfiguration.class))
                .run(context -> assertThat(context).hasNotFailed()
                        .doesNotHaveBean(CryptoServer.class)
                        .doesNotHaveBean(VaultKeySynchronizer.class)
                        .hasBean("cryptoProtocolConfigurer")
                        .hasBean("cryptoExceptionHandler"));
    }

    @Test
    void disabledCryptoDoesNotAccessVaultEvenWhenSynchronizerIsScanned() {
        VaultTemplate template = mock(VaultTemplate.class);
        webRunner.withUserConfiguration(VaultKeySynchronizer.class)
                .withBean(VaultTemplate.class, () -> template)
                .withPropertyValues("sensitive.transport.crypto.enabled=false")
                .run(context -> {
                    assertThat(context).hasNotFailed()
                            .doesNotHaveBean(CryptoServer.class)
                            .doesNotHaveBean(VaultKeySynchronizer.class);
                    verify(template).afterPropertiesSet();
                    verifyNoMoreInteractions(template);
                });
    }

    @Test
    void disabledCryptoDoesNotRequireVaultEvenWhenSynchronizerIsScanned() {
        webRunner.withUserConfiguration(VaultKeySynchronizer.class)
                .withPropertyValues("sensitive.transport.crypto.enabled=false")
                .run(context -> assertThat(context).hasNotFailed()
                        .doesNotHaveBean(CryptoServer.class)
                        .doesNotHaveBean(VaultKeySynchronizer.class));
    }

    @Test
    void nestedConfigurationIsValidated() {
        webRunner.withPropertyValues(
                "sensitive.transport.crypto.vault.cas-max-retries=0").run(context ->
                assertThat(context).hasFailed());
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
