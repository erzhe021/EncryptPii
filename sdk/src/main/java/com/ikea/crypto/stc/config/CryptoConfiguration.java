package com.ikea.crypto.stc.config;

import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.key.CryptoServer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

@Configuration
public class CryptoConfiguration {

    @Bean
    public CryptoServer ecdhCryptoServer(
            @Value("${sensitive.transport.crypto.vault.enabled:true}") boolean vaultEnabled,
            @Value("${sensitive.transport.crypto.vault.addr:http://127.0.0.1:8200}") String vaultAddr,
            @Value("${sensitive.transport.crypto.vault.token:root}") String vaultToken,
            @Value("${sensitive.transport.crypto.vault.ecdsa-secret-path:sensitive-transport/ecdsa-ciam}") String ecdsaSecretPath,
            @Value("${sensitive.transport.crypto.vault.aes-secret-path:sensitive-transport/aes-ciam}") String aesSecretPath
    ) throws GeneralSecurityException, IOException, InterruptedException {
        if (vaultEnabled) {
            return CryptoServer.createFromVault(vaultAddr, vaultToken, ecdsaSecretPath, aesSecretPath);
        }
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyGen.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        KeyPair keyPair = keyGen.generateKeyPair();
        KeyGenerator masterKeyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        masterKeyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey masterKey = masterKeyGenerator.generateKey();
        return new CryptoServer(keyPair.getPrivate(), keyPair.getPublic(), masterKey);
    }
}
