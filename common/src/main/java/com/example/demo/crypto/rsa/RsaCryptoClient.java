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

/**
 * RsaCryptoClient is a client-side implementation of RSA encryption and decryption.
 * It provides methods to encrypt and decrypt data using a hybrid RSA-AES encryption scheme.
 * The class fetches the server's RSA public key, generates a random AES session key,
 * encrypts the data with AES, and then encrypts the AES session key with the server's RSA public key.
 */
public class RsaCryptoClient {
    private final PublicKeyProvider publicKeyProvider;
    private final SecureRandom secureRandom;
    private SecretKey sessionKey;

    /**
     * Constructs a new RsaCryptoClient with the given PublicKeyProvider.
     *
     * @param publicKeyProvider The PublicKeyProvider used to fetch the server's RSA public key.
     */
    public RsaCryptoClient(PublicKeyProvider publicKeyProvider) {
        this.publicKeyProvider = publicKeyProvider;
        this.secureRandom = new SecureRandom();
    }

    /**
     * Encrypts the given data using a hybrid RSA-AES encryption scheme.
     * The data is encrypted with a randomly generated AES session key, which is then encrypted with the server's RSA public key.
     *
     * @param data The plaintext data to encrypt.
     * @return An RsaCipherPayload containing the encrypted AES session key, IV, and encrypted data.
     * @throws GeneralSecurityException If encryption fails due to cryptographic errors.
     */
    public RsaCipherPayload encrypt(String data) throws GeneralSecurityException {
        // Fetch the server's RSA public key
        RsaPublicKeyResponse publicKeyResponse = (RsaPublicKeyResponse) publicKeyProvider.fetchServerPublicKey();
        PublicKey serverPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(publicKeyResponse.publicKeyBase64()))
        );

        // Generate a random AES session key
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS, secureRandom);
        this.sessionKey = keyGenerator.generateKey();

        // Generate a random IV for AES encryption
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);

        // Encrypt the data with AES using the session key and IV
        byte[] encryptedData = encryptWithAes(data, sessionKey, iv);

        // Encrypt the AES session key with the server's RSA public key
        Cipher rsaCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedSessionKey = rsaCipher.doFinal(sessionKey.getEncoded());

        // Return the encrypted payload containing the encrypted session key, IV, and encrypted data
        return new RsaCipherPayload(
                EncodingUtils.toBase64(encryptedSessionKey),
                EncodingUtils.toBase64(iv),
                EncodingUtils.toBase64(encryptedData)
        );
    }

    /**
     * Decrypts the given RsaCipherPayload using the locally stored AES session key.
     *
     * @param payload The RsaCipherPayload containing the encrypted data and IV.
     * @return The decrypted plaintext string.
     * @throws GeneralSecurityException If decryption fails due to cryptographic errors.
     * @throws IllegalArgumentException If the payload is null.
     * @throws IllegalStateException    If the AES session key is not available for decryption.
     */
    public String decrypt(RsaCipherPayload payload) throws GeneralSecurityException {
        if (payload == null) {
            throw new IllegalArgumentException("payload cannot be null");
        }
        if (sessionKey == null) {
            throw new IllegalStateException("No AES session key available for local RSA decryption");
        }
        // Decrypt the data using AES with the locally stored session key and the provided IV
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(
                Cipher.DECRYPT_MODE,
                sessionKey,
                new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, EncodingUtils.fromBase64(payload.ivBase64()))
        );
        // Decrypt the encrypted data and return the plaintext string
        byte[] plainBytes = aesCipher.doFinal(EncodingUtils.fromBase64(payload.encryptedDataBase64()));
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    /**
     * Encrypts the given data using AES encryption with the provided session key and IV.
     *
     * @param data       The plaintext data to encrypt.
     * @param sessionKey The AES session key used for encryption.
     * @param iv         The initialization vector (IV) used for AES encryption.
     * @return The encrypted byte array of the data.
     * @throws GeneralSecurityException If encryption fails due to cryptographic errors.
     */
    private byte[] encryptWithAes(String data, SecretKey sessionKey, byte[] iv) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
        return aesCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }
}
