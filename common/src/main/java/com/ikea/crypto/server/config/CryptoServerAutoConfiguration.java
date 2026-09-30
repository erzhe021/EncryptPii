package com.ikea.crypto.server.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.server.advice.RequestDecryptAdvice;
import com.ikea.crypto.server.advice.ResponseEncryptAdvice;
import com.ikea.crypto.server.codec.CryptoPayloadHandler;
import com.ikea.crypto.server.endpoint.CryptoKeyEndpoint;
import com.ikea.crypto.server.error.CryptoExceptionHandler;
import com.ikea.crypto.server.service.CryptoServer;
import com.ikea.crypto.server.vault.VaultClient;
import com.ikea.crypto.server.vault.VaultKeyRing;
import com.ikea.crypto.server.vault.VaultProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * Spring Boot AutoConfiguration for Crypto Server SDK.
 */
@Slf4j
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(RequestBodyAdvice.class)
@ConditionalOnProperty(prefix = "crypto.server", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({CryptoServerProperties.class, VaultProperties.class})
public class CryptoServerAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public CryptoServer cryptoServer(VaultProperties vaultProperties) throws GeneralSecurityException, IOException {
        if (vaultProperties != null && vaultProperties.isEnabled()) {
            log.info("Vault key management enabled. Loading and managing keys via Vault at {}", vaultProperties.getAddr());
            VaultClient vaultClient = new VaultClient(vaultProperties.getAddr());
            VaultKeyRing vaultKeyRing = new VaultKeyRing(vaultProperties, vaultClient);
            vaultKeyRing.initialize();
            return new CryptoServer(vaultKeyRing);
        }

        log.warn("Vault key management is disabled (crypto.vault.enabled=false). Initializing CryptoServer with an in-memory RSA keypair for local/testing environment.");
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        keyGen.initialize(CryptoConstants.RSA_KEY_SIZE_BITS);
        KeyPair keyPair = keyGen.generateKeyPair();
        return new CryptoServer(keyPair.getPrivate(), keyPair.getPublic());
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
    @ConditionalOnProperty(prefix = "crypto.server.exception-handler", name = "enabled", havingValue = "true", matchIfMissing = true)
    public CryptoExceptionHandler cryptoExceptionHandler() {
        return new CryptoExceptionHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "crypto.server.endpoint", name = "enabled", havingValue = "true", matchIfMissing = true)
    public CryptoKeyEndpoint cryptoKeyEndpoint(CryptoServer cryptoServer) {
        return new CryptoKeyEndpoint(cryptoServer);
    }
}
