package com.example.demo.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class HybridCryptoServer {
    private final PrivateKey rsaPrivateKey;
    private final PublicKey rsaPublicKey;
    private final PrivateKey ecdhPrivateKey;
    private final PublicKey ecdhPublicKey;

    public HybridCryptoServer(
            PrivateKey rsaPrivateKey,
            PublicKey rsaPublicKey,
            PrivateKey ecdhPrivateKey,
            PublicKey ecdhPublicKey
    ) {
        this.rsaPrivateKey = rsaPrivateKey;
        this.rsaPublicKey = rsaPublicKey;
        this.ecdhPrivateKey = ecdhPrivateKey;
        this.ecdhPublicKey = ecdhPublicKey;
    }

    public static HybridCryptoServer create(Path keyDirectory) throws GeneralSecurityException, IOException {
        Files.createDirectories(keyDirectory);

        KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
        KeyPair rsaKeyPair = loadOrCreateKeyPair(
                keyDirectory.resolve("rsa-private-key.pkcs8"),
                keyDirectory.resolve("rsa-public-key.x509"),
                "RSA",
                rsaKeyFactory,
                2048,
                null
        );
        KeyFactory ecdhKeyFactory = KeyFactory.getInstance(CryptoConstants.ECDH_ALGORITHM);
        KeyPair ecdhKeyPair = loadOrCreateKeyPair(
                keyDirectory.resolve("ecdh-private-key.pkcs8"),
                keyDirectory.resolve("ecdh-public-key.x509"),
                CryptoConstants.ECDH_ALGORITHM,
                ecdhKeyFactory,
                0,
                CryptoConstants.ECDH_CURVE
        );
        return new HybridCryptoServer(
                rsaKeyPair.getPrivate(),
                rsaKeyPair.getPublic(),
                ecdhKeyPair.getPrivate(),
                ecdhKeyPair.getPublic()
        );
    }

    private static KeyPair loadOrCreateKeyPair(
            Path privateKeyPath,
            Path publicKeyPath,
            String algorithm,
            KeyFactory keyFactory,
            int keySize,
            String curve
    ) throws GeneralSecurityException, IOException {
        if (Files.exists(privateKeyPath) && Files.exists(publicKeyPath)) {
            PrivateKey privateKey = keyFactory.generatePrivate(
                    new PKCS8EncodedKeySpec(Files.readAllBytes(privateKeyPath))
            );
            PublicKey publicKey = keyFactory.generatePublic(
                    new X509EncodedKeySpec(Files.readAllBytes(publicKeyPath))
            );
            return new KeyPair(publicKey, privateKey);
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
        if (curve == null) {
            generator.initialize(keySize);
        } else {
            generator.initialize(new ECGenParameterSpec(curve));
        }
        KeyPair keyPair = generator.generateKeyPair();
        Files.write(privateKeyPath, keyPair.getPrivate().getEncoded());
        Files.write(publicKeyPath, keyPair.getPublic().getEncoded());
        return keyPair;
    }

    public PublicKey publicKey() {
        return rsaPublicKey;
    }

    public PublicKey rsaPublicKey() {
        return rsaPublicKey;
    }

    public PublicKey ecdhPublicKey() {
        return ecdhPublicKey;
    }

    public String decryptPhone(HybridCipherPayload payload) throws GeneralSecurityException {
        if (payload.clientEphemeralPublicKeyBase64() == null || payload.clientEphemeralPublicKeyBase64().isBlank()) {
            return decryptRsaPhone(payload);
        }
        return decryptEcdhPhone(payload);
    }

    public String decryptRsaPhone(HybridCipherPayload payload) throws GeneralSecurityException {
        Cipher rsaCipher = Cipher.getInstance(CryptoConstants.RSA_TRANSFORMATION);
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(EncodingUtils.fromBase64(payload.encryptedAesKeyBase64()));
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        return decryptWithAes(payload, aesKey);
    }

    public String decryptEcdhPhone(HybridCipherPayload payload) throws GeneralSecurityException {
        PublicKey clientEphemeralPublicKey = KeyFactory.getInstance(CryptoConstants.ECDH_ALGORITHM).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(payload.clientEphemeralPublicKeyBase64()))
        );
        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ECDH_KEY_AGREEMENT);
        keyAgreement.init(ecdhPrivateKey);
        keyAgreement.doPhase(clientEphemeralPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        byte[] derivedAesKey = HkdfUtils.deriveAesKey(
                sharedSecret,
                EncodingUtils.fromBase64(payload.ivBase64()),
                "phone-aes-key".getBytes(StandardCharsets.UTF_8),
                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
        );
        SecretKey aesKey = new SecretKeySpec(derivedAesKey, "AES");
        return decryptWithAes(payload, aesKey);
    }

    private String decryptWithAes(HybridCipherPayload payload, SecretKey aesKey) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.AES_TRANSFORMATION);
        aesCipher.init(
                Cipher.DECRYPT_MODE,
                aesKey,
                new GCMParameterSpec(
                        CryptoConstants.GCM_TAG_LENGTH_BITS,
                        EncodingUtils.fromBase64(payload.ivBase64())
                )
        );
        byte[] plainBytes = aesCipher.doFinal(EncodingUtils.fromBase64(payload.encryptedPhoneBase64()));
        return new String(plainBytes, StandardCharsets.UTF_8);
    }
}
