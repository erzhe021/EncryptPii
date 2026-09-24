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
                keyDirectory.resolve("ecdsa-private-key.pkcs8"),
                keyDirectory.resolve("ecdsa-public-key.x509"),
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
        if (EcdhCryptoConfiguration.oneTimeUsedKey) {
            ephemeralEcdhPrivateKeys.invalidate(serverPublicKeyBase64);
        }
        return decryptedValue;
    }

    public EcdhCipherPayload encrypt(String data) throws GeneralSecurityException {
        EcdhPublicKeyResponse publicKeyResponse = generateEphemeralEcdhPublicKey();
        return encryptWithServerPublicKey(data, publicKeyResponse.ephemeralPublicKeyBase64(), false);
    }

    public EcdhCipherPayload encryptWithRequestPayload(String data, EcdhCipherPayload requestPayload) throws GeneralSecurityException {
        if (requestPayload == null) {
            return encrypt(data);
        }
        validatePayload(requestPayload);
        String serverPublicKeyBase64 = requestPayload.serverEphemeralPublicKeyBase64();
        PrivateKey serverPrivateKey = ephemeralEcdhPrivateKeys.getIfPresent(serverPublicKeyBase64);
        if (serverPrivateKey == null) {
            throw new IllegalArgumentException("No matching ephemeral server private key found for response encryption");
        }
        return encryptWithServerPrivateKeyAndClientPublicKey(
                data,
                requestPayload,
                serverPrivateKey,
                requestPayload.clientEphemeralPublicKeyBase64()
        );
    }

    private EcdhCipherPayload encryptWithServerPublicKey(String data, String serverPublicKeyBase64, boolean reuseSameServerEphemeralKey) throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyPairGenerator.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        KeyPair clientEphemeralKeyPair = keyPairGenerator.generateKeyPair();

        PublicKey serverPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(serverPublicKeyBase64))
        );
        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        keyAgreement.init(clientEphemeralKeyPair.getPrivate());
        keyAgreement.doPhase(serverPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);
        byte[] derivedAesKey = HkdfUtils.deriveAesKey(
                sharedSecret,
                iv,
                CryptoConstants.HKDF_INFO_DATA_AES_KEY.getBytes(StandardCharsets.UTF_8),
                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
        );
        SecretKey aesKey = new SecretKeySpec(derivedAesKey, CryptoConstants.ALGORITHM_AES);
        byte[] encryptedData = encryptWithAes(data, aesKey, iv);

        return new EcdhCipherPayload(
                EncodingUtils.toBase64(clientEphemeralKeyPair.getPublic().getEncoded()),
                serverPublicKeyBase64,
                EncodingUtils.toBase64(iv),
                EncodingUtils.toBase64(encryptedData)
        );
    }

    private EcdhCipherPayload encryptWithServerPrivateKeyAndClientPublicKey(
            String data,
            EcdhCipherPayload requestPayload,
            PrivateKey serverPrivateKey,
            String clientPublicKeyBase64
    ) throws GeneralSecurityException {
        PublicKey clientEphemeralPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(clientPublicKeyBase64))
        );
        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        keyAgreement.init(serverPrivateKey);
        keyAgreement.doPhase(clientEphemeralPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);
        byte[] derivedAesKey = HkdfUtils.deriveAesKey(
                sharedSecret,
                iv,
                CryptoConstants.HKDF_INFO_DATA_AES_KEY.getBytes(StandardCharsets.UTF_8),
                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
        );
        SecretKey aesKey = new SecretKeySpec(derivedAesKey, CryptoConstants.ALGORITHM_AES);
        byte[] encryptedData = encryptWithAes(data, aesKey, iv);

        return new EcdhCipherPayload(
                requestPayload.clientEphemeralPublicKeyBase64(),
                requestPayload.serverEphemeralPublicKeyBase64(),
                EncodingUtils.toBase64(iv),
                EncodingUtils.toBase64(encryptedData)
        );
    }

    public String decryptEcdhData(EcdhCipherPayload payload) throws GeneralSecurityException {
        return decrypt(payload);
    }

    private void validatePayload(EcdhCipherPayload payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Payload cannot be null");
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

    private byte[] encryptWithAes(String data, SecretKey aesKey, byte[] iv) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
        return aesCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }
}
