package com.ikea.crypto.stc.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.exception.CryptoExceptionHandler;
import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.web.advice.RequestDecryptAdvice;
import com.ikea.crypto.stc.web.advice.ResponseEncryptAdvice;
import com.ikea.crypto.stc.web.endpoint.CryptoKeyEndpoint;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdvice;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(RequestBodyAdvice.class)
@ConditionalOnProperty(prefix = "sensitive.transport.crypto", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(SensitiveTransportCryptoProperties.class)
public class SensitiveTransportCryptoAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public CryptoServer cryptoServer() throws GeneralSecurityException, IOException {
        Path keyDir = resolveKeyDirectory();
        if (Files.exists(keyDir.resolve("ecdsa-private-key.pkcs8")) && Files.exists(keyDir.resolve("ecdsa-public-key.x509"))
                && Files.exists(keyDir.resolve("ecdh-ticket-master-key.aes"))) {
            return CryptoServer.create(keyDir);
        }

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair keyPair = keyGen.generateKeyPair();

        KeyGenerator masterKeyGenerator = KeyGenerator.getInstance("AES");
        masterKeyGenerator.init(256);
        SecretKey masterKey = masterKeyGenerator.generateKey();
        return new CryptoServer(keyPair.getPrivate(), keyPair.getPublic(), masterKey);
    }

    @Bean
    @ConditionalOnMissingBean
    public RequestDecryptAdvice requestDecryptAdvice(CryptoServer cryptoServer, ObjectMapper objectMapper) {
        return new RequestDecryptAdvice(cryptoServer, objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public ResponseEncryptAdvice responseEncryptAdvice(CryptoServer cryptoServer, ObjectMapper objectMapper) {
        return new ResponseEncryptAdvice(cryptoServer, objectMapper);
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

    private Path resolveKeyDirectory() {
        Path localKeys = Path.of("src/main/resources/keys");
        if (Files.exists(localKeys)) {
            return localKeys;
        }
        return Path.of("server/src/main/resources/keys");
    }
}
