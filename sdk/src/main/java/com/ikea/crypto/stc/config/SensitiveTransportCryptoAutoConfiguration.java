package com.ikea.crypto.stc.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.exception.CryptoExceptionHandler;
import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.vault.VaultClient;
import com.ikea.crypto.stc.vault.VaultKeyRing;
import com.ikea.crypto.stc.web.advice.RequestDecryptAdvice;
import com.ikea.crypto.stc.web.advice.ResponseEncryptAdvice;
import com.ikea.crypto.stc.web.codec.CryptoPayloadHandler;
import com.ikea.crypto.stc.web.endpoint.CryptoKeyEndpoint;
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
 * Auto-configuration for sensitive transport cryptography in Spring Boot applications.
 * <p>
 * This configuration sets up the necessary beans for handling cryptographic operations,
 * including key management via HashiCorp Vault or an in-memory RSA keypair for local/testing environments.
 * It also configures request/response encryption and decryption advice, as well as optional exception handling and key endpoints.
 */
@Slf4j
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(RequestBodyAdvice.class)
@ConditionalOnProperty(prefix = "sensitive.transport.crypto", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({SensitiveTransportCryptoProperties.class, VaultProperties.class})
public class SensitiveTransportCryptoAutoConfiguration {

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

        log.warn("Vault key management is disabled. Initializing CryptoServer with an in-memory RSA keypair for local/testing environment.");
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
    @ConditionalOnProperty(prefix = "sensitive.transport.crypto.exception-handler", name = "enabled", havingValue = "true", matchIfMissing = true)
    public CryptoExceptionHandler cryptoExceptionHandler() {
        return new CryptoExceptionHandler();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "sensitive.transport.crypto.endpoint", name = "enabled", havingValue = "true", matchIfMissing = true)
    public CryptoKeyEndpoint cryptoKeyEndpoint(CryptoServer cryptoServer) {
        return new CryptoKeyEndpoint(cryptoServer);
    }
}
