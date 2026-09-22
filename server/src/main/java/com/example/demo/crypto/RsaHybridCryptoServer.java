package com.example.demo.crypto;

import org.springframework.util.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RsaHybridCryptoServer {
    private final PrivateKey rsaPrivateKey;
    private final PublicKey rsaPublicKey;

    public RsaHybridCryptoServer(PrivateKey rsaPrivateKey, PublicKey rsaPublicKey) {
        this.rsaPrivateKey = rsaPrivateKey;
        this.rsaPublicKey = rsaPublicKey;
    }

    public static RsaHybridCryptoServer create(Path keyDirectory) throws GeneralSecurityException, IOException {
        Files.createDirectories(keyDirectory);
        KeyFactory rsaKeyFactory = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA);
        KeyPair rsaKeyPair = loadOrCreateKeyPair(
                keyDirectory.resolve("rsa-private-key.pkcs8"),
                keyDirectory.resolve("rsa-public-key.x509"),
                rsaKeyFactory,
                2048
        );
        return new RsaHybridCryptoServer(rsaKeyPair.getPrivate(), rsaKeyPair.getPublic());
    }

    private static KeyPair loadOrCreateKeyPair(Path privateKeyPath, Path publicKeyPath, KeyFactory keyFactory, int keySize)
            throws GeneralSecurityException, IOException {
        if (Files.exists(privateKeyPath) && Files.exists(publicKeyPath)) {
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(privateKeyPath)));
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(publicKeyPath)));
            return new KeyPair(publicKey, privateKey);
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        generator.initialize(keySize);
        KeyPair keyPair = generator.generateKeyPair();
        Files.write(privateKeyPath, keyPair.getPrivate().getEncoded());
        Files.write(publicKeyPath, keyPair.getPublic().getEncoded());
        return keyPair;
    }

    public PublicKey rsaPublicKey() {
        return rsaPublicKey;
    }

    public String decrypt(RsaHybridCipherPayload payload) throws GeneralSecurityException {
        validatePayload(payload);
        Cipher rsaCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(EncodingUtils.fromBase64(payload.encryptedAesKeyBase64()));
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, CryptoConstants.ALGORITHM_AES);
        return decryptWithAes(payload, aesKey);
    }

    public String decryptRsaData(RsaHybridCipherPayload payload) throws GeneralSecurityException {
        return decrypt(payload);
    }

    private void validatePayload(RsaHybridCipherPayload payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Payload cannot be null");
        }
        if (!StringUtils.hasLength(payload.algorithm())) {
            throw new IllegalArgumentException("Algorithm is required but was not provided.");
        }
        if (!StringUtils.hasLength(payload.encryptedAesKeyBase64())) {
            throw new IllegalArgumentException("Encrypted AES key is required for RSA decryption but was not provided.");
        }
        if (!StringUtils.hasLength(payload.ivBase64())) {
            throw new IllegalArgumentException("IV is required but was not provided.");
        }
        if (!StringUtils.hasLength(payload.encryptedDataBase64())) {
            throw new IllegalArgumentException("Encrypted data is required but was not provided.");
        }
    }

    private String decryptWithAes(RsaHybridCipherPayload payload, SecretKey aesKey) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(
                Cipher.DECRYPT_MODE,
                aesKey,
                new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, EncodingUtils.fromBase64(payload.ivBase64()))
        );
        byte[] plainBytes = aesCipher.doFinal(EncodingUtils.fromBase64(payload.encryptedDataBase64()));
        return new String(plainBytes, StandardCharsets.UTF_8);
    }
}
