package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhPublicKeyResponse;
import com.example.demo.crypto.ecdh.HkdfUtils;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import lombok.Getter;
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
import java.time.Duration;

public class EcdhCryptoServer {
    public static final Duration DEFAULT_EPHEMERAL_KEY_TTL = Duration.ofMinutes(5);
    public static final long DEFAULT_MAX_EPHEMERAL_KEYS = 10000L;

    @Getter
    private final PrivateKey longTermIdentityPrivateKey;
    @Getter
    private final PublicKey longTermIdentityPublicKey;

    private final Cache<String, PrivateKey> ephemeralEcdhPrivateKeys;

    public EcdhCryptoServer(PrivateKey longTermIdentityPrivateKey, PublicKey longTermIdentityPublicKey) {
        this(longTermIdentityPrivateKey, longTermIdentityPublicKey, DEFAULT_EPHEMERAL_KEY_TTL, DEFAULT_MAX_EPHEMERAL_KEYS);
    }

    public EcdhCryptoServer(
            PrivateKey longTermIdentityPrivateKey,
            PublicKey longTermIdentityPublicKey,
            Duration ephemeralKeyTtl,
            long maxEphemeralKeys
    ) {
        if (ephemeralKeyTtl == null || ephemeralKeyTtl.isZero() || ephemeralKeyTtl.isNegative()) {
            throw new IllegalArgumentException("Ephemeral key TTL must be greater than zero.");
        }
        if (maxEphemeralKeys <= 0) {
            throw new IllegalArgumentException("Maximum ephemeral key count must be greater than zero.");
        }
        this.longTermIdentityPrivateKey = longTermIdentityPrivateKey;
        this.longTermIdentityPublicKey = longTermIdentityPublicKey;
        this.ephemeralEcdhPrivateKeys = Caffeine.newBuilder()
                .expireAfterWrite(ephemeralKeyTtl)
                .maximumSize(maxEphemeralKeys)
                .build();
    }

    public static EcdhCryptoServer create(Path keyDirectory) throws GeneralSecurityException, IOException {
        Files.createDirectories(keyDirectory);
        KeyFactory ecdhKeyFactory = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC);
        KeyPair identityKeyPair = loadOrCreateKeyPair(
                keyDirectory.resolve("ecdh-identity-private-key.pkcs8"),
                keyDirectory.resolve("ecdh-identity-public-key.x509"),
                ecdhKeyFactory,
                CryptoConstants.CURVE_ECDH
        );
        return new EcdhCryptoServer(identityKeyPair.getPrivate(), identityKeyPair.getPublic());
    }

    private static KeyPair loadOrCreateKeyPair(Path privateKeyPath, Path publicKeyPath, KeyFactory keyFactory, String curve)
            throws GeneralSecurityException, IOException {
        if (Files.exists(privateKeyPath) && Files.exists(publicKeyPath)) {
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(privateKeyPath)));
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(publicKeyPath)));
            return new KeyPair(publicKey, privateKey);
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        generator.initialize(new ECGenParameterSpec(curve));
        KeyPair keyPair = generator.generateKeyPair();
        Files.write(privateKeyPath, keyPair.getPrivate().getEncoded());
        Files.write(publicKeyPath, keyPair.getPublic().getEncoded());
        return keyPair;
    }

    public EcdhPublicKeyResponse generateEphemeralEcdhPublicKey() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyPairGenerator.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        KeyPair ephemeralKeyPair = keyPairGenerator.generateKeyPair();
        byte[] ephemeralPublicKeyBytes = ephemeralKeyPair.getPublic().getEncoded();
        String ephemeralPublicKeyBase64 = EncodingUtils.toBase64(ephemeralPublicKeyBytes);
        ephemeralEcdhPrivateKeys.put(ephemeralPublicKeyBase64, ephemeralKeyPair.getPrivate());

        byte[] identityPublicKeyBytes = longTermIdentityPublicKey.getEncoded();
        String identityPublicKeyBase64 = EncodingUtils.toBase64(identityPublicKeyBytes);
        Signature signature = Signature.getInstance(CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA);
        signature.initSign(longTermIdentityPrivateKey);
        signature.update(ephemeralPublicKeyBytes);
        byte[] signatureBytes = signature.sign();
        String signatureBase64 = EncodingUtils.toBase64(signatureBytes);

        return new EcdhPublicKeyResponse(
                CryptoConstants.ALGORITHM_ECDH,
                CryptoConstants.CURVE_ECDH,
                ephemeralPublicKeyBase64,
                identityPublicKeyBase64,
                CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA,
                signatureBase64
        );
    }

    public String decrypt(EcdhCipherPayload payload) throws GeneralSecurityException {
        validatePayload(payload);
        String serverPublicKeyBase64 = payload.serverEphemeralPublicKeyBase64();
        PrivateKey serverPrivateKey = ephemeralEcdhPrivateKeys.getIfPresent(serverPublicKeyBase64);
        if (serverPrivateKey == null) {
            throw new IllegalArgumentException(
                    "No matching ephemeral server private key found for this ECDH request. " +
                            "Session key generation must use a fresh ephemeral key pair only."
            );
        }

        PublicKey clientEphemeralPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(payload.clientEphemeralPublicKeyBase64()))
        );
        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        keyAgreement.init(serverPrivateKey);
        keyAgreement.doPhase(clientEphemeralPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        byte[] derivedAesKey = HkdfUtils.deriveAesKey(
                sharedSecret,
                EncodingUtils.fromBase64(payload.ivBase64()),
                CryptoConstants.HKDF_INFO_DATA_AES_KEY.getBytes(StandardCharsets.UTF_8),
                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
        );

        SecretKey aesKey = new SecretKeySpec(derivedAesKey, CryptoConstants.ALGORITHM_AES);
        String decryptedValue = decryptWithAes(payload, aesKey);
        ephemeralEcdhPrivateKeys.invalidate(serverPublicKeyBase64);
        return decryptedValue;
    }

    public String decryptEcdhData(EcdhCipherPayload payload) throws GeneralSecurityException {
        return decrypt(payload);
    }

    private void validatePayload(EcdhCipherPayload payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Payload cannot be null");
        }
        if (!StringUtils.hasLength(payload.algorithm())) {
            throw new IllegalArgumentException("Algorithm is required but was not provided.");
        }
        if (!StringUtils.hasLength(payload.clientEphemeralPublicKeyBase64())) {
            throw new IllegalArgumentException("Client ephemeral public key is required for ECDH decryption but was not provided.");
        }
        if (!StringUtils.hasLength(payload.serverEphemeralPublicKeyBase64())) {
            throw new IllegalArgumentException("Server ephemeral public key is required for ECDH Ephemeral decryption but was not provided.");
        }
        if (!StringUtils.hasLength(payload.ivBase64())) {
            throw new IllegalArgumentException("IV is required but was not provided.");
        }
        if (!StringUtils.hasLength(payload.encryptedDataBase64())) {
            throw new IllegalArgumentException("Encrypted data is required but was not provided.");
        }
    }

    private String decryptWithAes(EcdhCipherPayload payload, SecretKey aesKey) throws GeneralSecurityException {
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
