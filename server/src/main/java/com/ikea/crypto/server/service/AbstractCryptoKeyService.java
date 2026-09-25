package com.ikea.crypto.server.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
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

    public static KeyPair loadOrCreateKeyPair(
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
