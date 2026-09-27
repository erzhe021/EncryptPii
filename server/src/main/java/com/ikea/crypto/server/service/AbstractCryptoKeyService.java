package com.ikea.crypto.server.service;

import com.ikea.crypto.common.CryptoConstants;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public abstract class AbstractCryptoKeyService {

    @FunctionalInterface
    public interface KeyPairInitializer {
        void initialize(KeyPairGenerator generator) throws GeneralSecurityException;
    }

    public static void ensureKeyDirectory(Path keyDirectory) throws IOException {
        Files.createDirectories(keyDirectory);
    }

    public static SecretKey loadOrCreateMasterKey(Path keyPath) throws IOException {
        if (Files.exists(keyPath)) {
            byte[] keyBytes = Files.readAllBytes(keyPath);
            return new SecretKeySpec(keyBytes, CryptoConstants.ALGORITHM_AES);
        }
        byte[] keyBytes = new byte[CryptoConstants.MASTER_KEY_SIZE_BYTES]; // 32 bytes = 256-bit AES Master Key
        new SecureRandom().nextBytes(keyBytes);
        Files.write(keyPath, keyBytes);
        return new SecretKeySpec(keyBytes, CryptoConstants.ALGORITHM_AES);
    }

    public static KeyPair loadOrCreateLongLivedKeyPair(
            Path privateKeyPath,
            Path publicKeyPath,
            KeyFactory keyFactory,
            KeyPairInitializer generatorInitializer
    ) throws GeneralSecurityException, IOException {
        if (Files.exists(privateKeyPath) && Files.exists(publicKeyPath)) {
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(privateKeyPath)));
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(publicKeyPath)));
            return new KeyPair(publicKey, privateKey);
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyFactory.getAlgorithm());
        if (generatorInitializer != null) {
            generatorInitializer.initialize(generator);
        }
        KeyPair keyPair = generator.generateKeyPair();
        Files.write(privateKeyPath, keyPair.getPrivate().getEncoded());
        Files.write(publicKeyPath, keyPair.getPublic().getEncoded());
        return keyPair;
    }
}
