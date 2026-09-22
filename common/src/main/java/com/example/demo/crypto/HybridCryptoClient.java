package com.example.demo.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;
import java.util.logging.Logger;

public class HybridCryptoClient {
    private static final Logger LOGGER = Logger.getLogger(HybridCryptoClient.class.getName());
    private final PublicKeyProvider publicKeyProvider;
    private final SecureRandom secureRandom;

    public HybridCryptoClient(PublicKeyProvider publicKeyProvider) {
        this.publicKeyProvider = publicKeyProvider;
        this.secureRandom = new SecureRandom();
    }

    public HybridCipherPayload encrypt(String data) throws GeneralSecurityException {
        PublicKeyResponse publicKeyResponse = publicKeyProvider.fetchServerPublicKey();
        String algorithm = publicKeyResponse.algorithm().toUpperCase(Locale.ROOT);
        return switch (algorithm) {
            case CryptoConstants.ALGORITHM_RSA -> encryptWithRsa(data, publicKeyResponse.publicKeyBase64());
            case CryptoConstants.ALGORITHM_ECDH -> encryptWithEcdh(data, publicKeyResponse.publicKeyBase64());
            default -> throw new GeneralSecurityException("Unsupported server key algorithm: " + algorithm);
        };
    }

    private HybridCipherPayload encryptWithRsa(String data, String publicKeyBase64)
            throws GeneralSecurityException {
        PublicKey serverPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(publicKeyBase64))
        );

        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS, secureRandom);
        SecretKey aesKey = keyGenerator.generateKey();
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        byte[] encryptedData = encryptWithAes(data, aesKey, iv);

        Cipher rsaCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        return new HybridCipherPayload(
                "RSA-OAEP + AES-256-GCM",
                EncodingUtils.toBase64(encryptedAesKey),
                null,
                EncodingUtils.toBase64(iv),
                EncodingUtils.toBase64(encryptedData)
        );
    }

    private HybridCipherPayload encryptWithEcdh(String data, String publicKeyBase64)
            throws GeneralSecurityException {
        LOGGER.info(() -> "ECDH step 1/5 [client]: agreed curve parameters curve="
                + CryptoConstants.CURVE_ECDH
                + ", keyAgreement=" + CryptoConstants.ALGORITHM_ECDH
                + ", KDF=HKDF-SHA256, symmetricCipher=AES-256-GCM");
        PublicKey serverPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(publicKeyBase64))
        );
        LOGGER.info(() -> "ECDH step 2/5 [client]: server public key B = b x G, base64 prefix="
                + abbreviateBase64(publicKeyBase64));
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyPairGenerator.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH), secureRandom);
        KeyPair ephemeralKeyPair = keyPairGenerator.generateKeyPair();
        String clientEphemeralPublicKeyBase64 = EncodingUtils.toBase64(ephemeralKeyPair.getPublic().getEncoded());
        LOGGER.info(() -> "ECDH step 2/5 [client]: client generated ephemeral key pair "
                + "(private key a hidden), public key A = a x G, base64 prefix="
                + abbreviateBase64(clientEphemeralPublicKeyBase64));
        LOGGER.info("ECDH step 3/5 [client]: exchanged public keys over public channel");

        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        keyAgreement.init(ephemeralKeyPair.getPrivate());
        keyAgreement.doPhase(serverPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        LOGGER.info(() -> "ECDH step 4/5 [client]: computed shared secret S = a x B = a x (b x G) = abG, "
                + "shared point/x-secret hash=" + shortFingerprint(sharedSecret));

        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        byte[] derivedAesKey = HkdfUtils.deriveAesKey(
                sharedSecret,
                iv,
                "data-aes-key".getBytes(StandardCharsets.UTF_8),
                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
        );
        SecretKey aesKey = new SecretKeySpec(derivedAesKey, CryptoConstants.ALGORITHM_AES);
        LOGGER.info(() -> "ECDH step 5/5 [client]: derived AES key from shared secret x-coordinate via "
                + "HKDF-SHA256, aesKey hash="
                + shortFingerprint(derivedAesKey)
                + ", iv=" + EncodingUtils.toBase64(iv));
        byte[] encryptedData = encryptWithAes(data, aesKey, iv);
        LOGGER.info("ECDH client payload ready: sending A(client ephemeral public key) + AES-GCM ciphertext");

        return new HybridCipherPayload(
                "ECDH-P256 + HKDF-SHA256 + AES-256-GCM",
                null,
                clientEphemeralPublicKeyBase64,
                EncodingUtils.toBase64(iv),
                EncodingUtils.toBase64(encryptedData)
        );
    }

    private byte[] encryptWithAes(String data, SecretKey aesKey, byte[] iv) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(
                Cipher.ENCRYPT_MODE,
                aesKey,
                new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv)
        );
        return aesCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
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
