package com.ikea.crypto.stc.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.constant.CryptoConstants;
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
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(RequestBodyAdvice.class)
@ConditionalOnProperty(prefix = "sensitive.transport.crypto", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties({SensitiveTransportCryptoProperties.class, VaultProperties.class})
public class SensitiveTransportCryptoAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public CryptoServer cryptoServer(VaultProperties vaultProperties) throws GeneralSecurityException, IOException, InterruptedException {
        if (vaultProperties.isEnabled()) {
            return CryptoServer.createFromVault(vaultProperties);
        }

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyGen.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        KeyPair ecdsaKeyPair = keyGen.generateKeyPair();

        KeyGenerator masterKeyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        masterKeyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey masterKey = masterKeyGenerator.generateKey();
        return new CryptoServer(ecdsaKeyPair.getPrivate(), ecdsaKeyPair.getPublic(), masterKey);
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

}
