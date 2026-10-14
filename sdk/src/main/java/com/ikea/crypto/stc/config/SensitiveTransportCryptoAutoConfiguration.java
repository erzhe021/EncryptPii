package com.ikea.crypto.stc.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.key.KeyRing;
import com.ikea.crypto.stc.model.KeyMetadata;
import com.ikea.crypto.stc.vault.VaultClient;
import com.ikea.crypto.stc.vault.VaultKeyRing;
import com.ikea.crypto.stc.web.advice.CryptoExceptionHandler;
import com.ikea.crypto.stc.web.advice.RequestDecryptAdvice;
import com.ikea.crypto.stc.web.advice.ResponseEncryptAdvice;
import com.ikea.crypto.stc.web.codec.CryptoPayloadHandler;
import com.ikea.crypto.stc.web.endpoint.PublicKeyEndpoint;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.util.Assert;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Autoconfiguration for sensitive transport cryptography in Spring Boot applications.
 * <p>
 * This configuration sets up the necessary beans for handling cryptographic operations,
 * including key management via HashiCorp Vault by default, or explicitly selected memory storage for development/testing.
 * It also configures request/response encryption and decryption advice and optional key endpoints.
 * Exceptions are propagated to the application's exception handlers.
 */
@Slf4j
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(RequestBodyAdvice.class)
@ConditionalOnProperty(prefix = "sensitive.transport.crypto", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(SensitiveTransportCryptoProperties.class)
public class SensitiveTransportCryptoAutoConfiguration {

    @Bean
    public CryptoTimeConfigurationValidator cryptoTimeConfigurationValidator(SensitiveTransportCryptoProperties cryptoProperties) {
        return new CryptoTimeConfigurationValidator(cryptoProperties);
    }

    @Bean
    @ConditionalOnMissingBean
    public CryptoServer cryptoServer(
            SensitiveTransportCryptoProperties cryptoProperties,
            ObjectProvider<VaultTemplate> vaultTemplateProvider
    ) throws GeneralSecurityException, IOException {
        if (cryptoProperties.getKeyStore() == SensitiveTransportCryptoProperties.KeyStore.MEMORY) {
            return createMemoryCryptoServer(cryptoProperties);
        }
        VaultProperties vaultProperties = cryptoProperties.getVault();
        KeyLifecycleProperties keyLifecycleProperties = cryptoProperties.getKeyLifecycle();
        if (vaultProperties == null || !vaultProperties.isEnabled()) {
            throw new IllegalStateException(
                    "Vault key management is required for key-store=VAULT: sensitive.transport.crypto.vault.enabled must be true");
        }
        Assert.hasText(vaultProperties.getSecretPath(),
                "sensitive.transport.crypto.vault.secret-path must be configured");
        Assert.hasText(vaultProperties.getKeyAlias(),
                "sensitive.transport.crypto.vault.key-alias must be configured");
        VaultTemplate vaultTemplate = vaultTemplateProvider.getIfAvailable();
        if (vaultTemplate == null) {
            throw new IllegalStateException("VaultTemplate is required: enable and configure Spring Cloud Vault");
        }
        log.info("Loading and managing keys via Spring Cloud Vault");
        VaultKeyRing vaultKeyRing = new VaultKeyRing(
                vaultProperties,
                keyLifecycleProperties,
                new VaultClient(vaultTemplate),
                cryptoProperties.isAutoRotate()
        );
        vaultKeyRing.initialize();
        return new CryptoServer(vaultKeyRing);
    }

    private CryptoServer createMemoryCryptoServer(SensitiveTransportCryptoProperties cryptoProperties)
            throws GeneralSecurityException {
        String alias = cryptoProperties.getMemory().getKeyAlias();
        Assert.hasText(alias, "sensitive.transport.crypto.memory.key-alias must not be blank");
        Assert.isTrue(!alias.contains(":"),
                "sensitive.transport.crypto.memory.key-alias must not contain ':'");
        KeyLifecycleProperties lifecycle = cryptoProperties.getKeyLifecycle();
        log.warn("Explicit MEMORY key storage selected for development/testing only. "
                + "RSA keys are not persisted, old ciphertext cannot be decrypted after restart, "
                + "and independent instances do not share keys.");
        KeyRing keyRing = new KeyRing(
                alias,
                lifecycle.getValidityMillis(),
                lifecycle.getGracePeriodMillis(),
                cryptoProperties.isAutoRotate(),
                lifecycle.getRotationBeforeExpiryMillis()
        );
        long now = System.currentTimeMillis();
        // Random numeric seed avoids restarting at version 1 and stays within JavaScript's safe integer range.
        long initialVersion = new SecureRandom().nextLong(1, 1L << 52);
        KeyMetadata metadata = new KeyMetadata(
                KeyMetadata.buildKeyId(keyRing.getKeyAlias(), initialVersion),
                now,
                now + lifecycle.getValidityMillis()
        );
        keyRing.registerKeyEntry(new KeyRing.KeyEntry(metadata, keyRing.generateKeyPair()), true);
        return new CryptoServer(keyRing);
    }

    @Bean
    @ConditionalOnMissingBean
    public CryptoPayloadHandler cryptoPayloadHandler(CryptoServer cryptoServer, ObjectMapper objectMapper) {
        return new CryptoPayloadHandler(cryptoServer, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public RequestDecryptAdvice requestDecryptAdvice(CryptoPayloadHandler payloadHandler) {
        return new RequestDecryptAdvice(payloadHandler);
    }

    @Bean
    @ConditionalOnMissingBean
    public ResponseEncryptAdvice responseEncryptAdvice(CryptoPayloadHandler payloadHandler) {
        return new ResponseEncryptAdvice(payloadHandler);
    }

    @Bean
    @ConditionalOnMissingBean
    public CryptoExceptionHandler cryptoExceptionHandler() {
        return new CryptoExceptionHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "sensitive.transport.crypto.endpoint", name = "enabled", havingValue = "true", matchIfMissing = true)
    public PublicKeyEndpoint publicKeyEndpoint(CryptoServer cryptoServer) {
        return new PublicKeyEndpoint(cryptoServer);
    }
}
