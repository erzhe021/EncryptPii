package com.example.demo.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;

public class HybridCryptoClient {
    private final PublicKeyProvider publicKeyProvider;
    private final SecureRandom secureRandom;

    public HybridCryptoClient(PublicKeyProvider publicKeyProvider) {
        this.publicKeyProvider = publicKeyProvider;
        this.secureRandom = new SecureRandom();
    }

    public HybridCipherPayload encryptPhone(String phoneNumber) throws GeneralSecurityException {
        PublicKeyResponse publicKeyResponse = publicKeyProvider.fetchServerPublicKey();
        String algorithm = publicKeyResponse.algorithm().toUpperCase(Locale.ROOT);
        return switch (algorithm) {
            case "RSA" -> encryptWithRsa(phoneNumber, publicKeyResponse.publicKeyBase64());
            case "ECDH" -> encryptWithEcdh(phoneNumber, publicKeyResponse.publicKeyBase64());
            default -> throw new GeneralSecurityException("Unsupported server key algorithm: " + algorithm);
        };
    }

    private HybridCipherPayload encryptWithRsa(String phoneNumber, String publicKeyBase64)
            throws GeneralSecurityException {
        PublicKey serverPublicKey = KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(publicKeyBase64))
        );

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS, secureRandom);
        SecretKey aesKey = keyGenerator.generateKey();
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        byte[] encryptedPhone = encryptPhoneWithAes(phoneNumber, aesKey, iv);

        Cipher rsaCipher = Cipher.getInstance(CryptoConstants.RSA_TRANSFORMATION);
        rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        return new HybridCipherPayload(
                "RSA-OAEP + AES-256-GCM",
                EncodingUtils.toBase64(encryptedAesKey),
                null,
                EncodingUtils.toBase64(iv),
                EncodingUtils.toBase64(encryptedPhone)
        );
    }

    private HybridCipherPayload encryptWithEcdh(String phoneNumber, String publicKeyBase64)
            throws GeneralSecurityException {
        PublicKey serverPublicKey = KeyFactory.getInstance(CryptoConstants.ECDH_ALGORITHM).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(publicKeyBase64))
        );
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CryptoConstants.ECDH_ALGORITHM);
        keyPairGenerator.initialize(new ECGenParameterSpec(CryptoConstants.ECDH_CURVE), secureRandom);
        KeyPair ephemeralKeyPair = keyPairGenerator.generateKeyPair();

        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ECDH_KEY_AGREEMENT);
        keyAgreement.init(ephemeralKeyPair.getPrivate());
        keyAgreement.doPhase(serverPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        byte[] derivedAesKey = HkdfUtils.deriveAesKey(
                sharedSecret,
                iv,
                "phone-aes-key".getBytes(StandardCharsets.UTF_8),
                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
        );
        SecretKey aesKey = new SecretKeySpec(derivedAesKey, "AES");
        byte[] encryptedPhone = encryptPhoneWithAes(phoneNumber, aesKey, iv);

        return new HybridCipherPayload(
                "ECDH-P256 + HKDF-SHA256 + AES-256-GCM",
                null,
                EncodingUtils.toBase64(ephemeralKeyPair.getPublic().getEncoded()),
                EncodingUtils.toBase64(iv),
                EncodingUtils.toBase64(encryptedPhone)
        );
    }

    private byte[] encryptPhoneWithAes(String phoneNumber, SecretKey aesKey, byte[] iv) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.AES_TRANSFORMATION);
        aesCipher.init(
                Cipher.ENCRYPT_MODE,
                aesKey,
                new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv)
        );
        return aesCipher.doFinal(phoneNumber.getBytes(StandardCharsets.UTF_8));
    }
}
