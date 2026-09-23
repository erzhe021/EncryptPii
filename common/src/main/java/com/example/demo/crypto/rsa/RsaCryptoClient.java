package com.example.demo.crypto.rsa;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.PublicKeyProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

public class RsaCryptoClient {
    private final PublicKeyProvider publicKeyProvider;
    private final SecureRandom secureRandom;
    private SecretKey aesKey;

    public RsaCryptoClient(PublicKeyProvider publicKeyProvider) {
        this.publicKeyProvider = publicKeyProvider;
        this.secureRandom = new SecureRandom();
    }

    public RsaCipherPayload encrypt(String data) throws GeneralSecurityException {
        RsaPublicKeyResponse publicKeyResponse = (RsaPublicKeyResponse) publicKeyProvider.fetchServerPublicKey();
        PublicKey serverPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(publicKeyResponse.publicKeyBase64()))
        );

        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS, secureRandom);
        this.aesKey = keyGenerator.generateKey();

        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        byte[] encryptedData = encryptWithAes(data, aesKey, iv);

        Cipher rsaCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        return new RsaCipherPayload(
                EncodingUtils.toBase64(encryptedAesKey),
                EncodingUtils.toBase64(iv),
                EncodingUtils.toBase64(encryptedData)
        );
    }

    public String decrypt(RsaCipherPayload payload) throws GeneralSecurityException {
        if (payload == null) {
            throw new IllegalArgumentException("payload cannot be null");
        }
        if (aesKey == null) {
            throw new IllegalStateException("No AES session key available for local RSA decryption");
        }

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
