package com.example.demo.crypto;

import org.springframework.util.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Logger;

public class HybridCryptoServer {
    private static final Logger LOGGER = Logger.getLogger(HybridCryptoServer.class.getName());
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

        KeyFactory rsaKeyFactory = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA);
        KeyPair rsaKeyPair = loadOrCreateKeyPair(
                keyDirectory.resolve("rsa-private-key.pkcs8"),
                keyDirectory.resolve("rsa-public-key.x509"),
                CryptoConstants.ALGORITHM_RSA,
                rsaKeyFactory,
                2048,
                null
        );
        KeyFactory ecdhKeyFactory = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC);
        KeyPair ecdhKeyPair = loadOrCreateKeyPair(
                keyDirectory.resolve("ecdh-private-key.pkcs8"),
                keyDirectory.resolve("ecdh-public-key.x509"),
                CryptoConstants.ALGORITHM_EC,
                ecdhKeyFactory,
                0,
                CryptoConstants.CURVE_ECDH
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

    public PublicKey rsaPublicKey() {
        return rsaPublicKey;
    }

    public PublicKey ecdhPublicKey() {
        return ecdhPublicKey;
    }

    public String decryptData(HybridCipherPayload payload) throws GeneralSecurityException {
        validatePayload(payload);
        if (payload.clientEphemeralPublicKeyBase64() == null || payload.clientEphemeralPublicKeyBase64().isBlank()) {
            return decryptRsaData(payload);
        }
        return decryptEcdhData(payload);
    }

    private void validatePayload(HybridCipherPayload payload) {

        if (payload == null) {
            throw new IllegalArgumentException("Payload cannot be null");
        }

        if (!StringUtils.hasLength(payload.algorithm())) {
            throw new IllegalArgumentException("Algorithm is required but was not provided.");
        }

        if (payload.clientEphemeralPublicKeyBase64() == null || payload.clientEphemeralPublicKeyBase64().isBlank()) {
            if (!StringUtils.hasLength(payload.encryptedAesKeyBase64())) {
                throw new IllegalArgumentException("Encrypted AES key is required for RSA decryption but was not provided.");
            }
        } else {
            if (!StringUtils.hasLength(payload.clientEphemeralPublicKeyBase64())) {
                throw new IllegalArgumentException("Client ephemeral public key is required for ECDH decryption but was not provided.");
            }
        }

        if (!StringUtils.hasLength(payload.ivBase64())) {
            throw new IllegalArgumentException("IV is required but was not provided.");
        }

        if (!StringUtils.hasLength(payload.encryptedDataBase64())) {
            throw new IllegalArgumentException("Encrypted data is required but was not provided.");
        }

    }

    private String decryptRsaData(HybridCipherPayload payload) throws GeneralSecurityException {
        Cipher rsaCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(EncodingUtils.fromBase64(payload.encryptedAesKeyBase64()));
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, CryptoConstants.ALGORITHM_AES);
        return decryptWithAes(payload, aesKey);
    }

    private String decryptEcdhData(HybridCipherPayload payload) throws GeneralSecurityException {
        LOGGER.info(() -> "ECDH step 1/5 [server]: agreed curve parameters curve="
                + CryptoConstants.CURVE_ECDH
                + ", keyAgreement=" + CryptoConstants.ALGORITHM_ECDH
                + ", KDF=HKDF-SHA256, symmetricCipher=AES-256-GCM");
        LOGGER.info(() -> "ECDH step 2/5 [server]: received client public key A = a x G, base64 prefix="
                + abbreviateBase64(payload.clientEphemeralPublicKeyBase64()));
        LOGGER.info(() -> "ECDH step 3/5 [server]: server owns static public key B = b x G, base64 prefix="
                + abbreviateBase64(EncodingUtils.toBase64(ecdhPublicKey.getEncoded())));
        PublicKey clientEphemeralPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(payload.clientEphemeralPublicKeyBase64()))
        );
        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        keyAgreement.init(ecdhPrivateKey);
        keyAgreement.doPhase(clientEphemeralPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        LOGGER.info(() -> "ECDH step 4/5 [server]: computed shared secret S = b x A = b x (a x G) = abG, "
                + "shared point/x-secret hash=" + shortFingerprint(sharedSecret));
        byte[] derivedAesKey = HkdfUtils.deriveAesKey(
                sharedSecret,
                EncodingUtils.fromBase64(payload.ivBase64()),
                "data-aes-key".getBytes(StandardCharsets.UTF_8),
                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
        );
        LOGGER.info(() -> "ECDH step 5/5 [server]: derived AES key from shared secret x-coordinate via "
                + "HKDF-SHA256, aesKey hash="
                + shortFingerprint(derivedAesKey)
                + ", iv=" + payload.ivBase64());
        SecretKey aesKey = new SecretKeySpec(derivedAesKey, CryptoConstants.ALGORITHM_AES);
        String data = decryptWithAes(payload, aesKey);
        LOGGER.info("ECDH server decrypt result: AES-GCM decryption completed successfully");
        return data;
    }

    private String decryptWithAes(HybridCipherPayload payload, SecretKey aesKey) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(
                Cipher.DECRYPT_MODE,
                aesKey,
                new GCMParameterSpec(
                        CryptoConstants.GCM_TAG_LENGTH_BITS,
                        EncodingUtils.fromBase64(payload.ivBase64())
                )
        );
        byte[] plainBytes = aesCipher.doFinal(EncodingUtils.fromBase64(payload.encryptedDataBase64()));
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    private static String abbreviateBase64(String value) {
        int previewLength = Math.min(24, value.length());
        return value.substring(0, previewLength) + "...";
    }

    private static String shortFingerprint(byte[] value) {
        String base64 = EncodingUtils.toBase64(value);
        return abbreviateBase64(base64);
    }
}
