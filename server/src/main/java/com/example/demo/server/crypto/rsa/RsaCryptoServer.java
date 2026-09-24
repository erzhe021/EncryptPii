package com.example.demo.server.crypto.rsa;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.crypto.rsa.RsaPublicKeyResponse;
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

/**
 * RsaCryptoServer is responsible for handling RSA encryption and decryption operations.
 * It manages the RSA key pair and provides methods to encrypt and decrypt data using RSA and AES algorithms.
 */
public record RsaCryptoServer(PrivateKey rsaPrivateKey, PublicKey rsaPublicKey) {

    /**
     * Returns the RSA public key in a response format suitable for clients.
     *
     * @return an instance of RsaPublicKeyResponse containing the Base64-encoded RSA public key
     */
    public RsaPublicKeyResponse getPublicKey() {
        return new RsaPublicKeyResponse(
                EncodingUtils.toBase64(rsaPublicKey.getEncoded())
        );
    }

    /**
     * Creates an instance of RsaCryptoServer by loading or generating RSA key pair from the specified directory.
     *
     * @param keyDirectory the directory where RSA keys are stored or will be generated
     * @return an instance of RsaCryptoServer
     * @throws GeneralSecurityException if a security exception occurs during key generation or loading
     * @throws IOException              if an I/O error occurs while accessing the key files
     */
    public static RsaCryptoServer create(Path keyDirectory) throws GeneralSecurityException, IOException {
        Files.createDirectories(keyDirectory);
        KeyFactory rsaKeyFactory = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA);
        KeyPair rsaKeyPair = loadOrCreateKeyPair(
                keyDirectory.resolve("rsa-private-key.pkcs8"),
                keyDirectory.resolve("rsa-public-key.x509"),
                rsaKeyFactory,
                2048
        );
        return new RsaCryptoServer(rsaKeyPair.getPrivate(), rsaKeyPair.getPublic());
    }

    /**
     * Loads an existing RSA key pair from the specified file paths or generates a new one if the files do not exist.
     *
     * @param privateKeyPath the path to the private key file
     * @param publicKeyPath  the path to the public key file
     * @param keyFactory     the KeyFactory instance for RSA
     * @param keySize        the size of the RSA key to generate if files do not exist
     * @return a KeyPair containing the loaded or generated RSA keys
     * @throws GeneralSecurityException if a security exception occurs during key generation or loading
     * @throws IOException              if an I/O error occurs while accessing the key files
     */
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

    /**
     * Decrypts the provided RsaCipherPayload using the RSA private key and AES session key.
     *
     * @param payload the RsaCipherPayload containing the encrypted data, IV, and encrypted AES key
     * @return the decrypted plaintext data as a String
     * @throws GeneralSecurityException if a security exception occurs during decryption
     */
    public String decrypt(RsaCipherPayload payload) throws GeneralSecurityException {
        validatePayload(payload);
        byte[] aesKeyBytes = decryptSessionKey(payload.encryptedAesKeyBase64());
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, CryptoConstants.ALGORITHM_AES);
        return decryptWithAes(payload, aesKey);
    }

    /**
     * Decrypts the provided Base64-encoded encrypted AES session key using the RSA private key.
     *
     * @param encryptedSessionKeyBase64 the Base64-encoded encrypted AES session key
     * @return the decrypted AES session key as a byte array
     * @throws GeneralSecurityException if a security exception occurs during decryption
     */
    public byte[] decryptSessionKey(String encryptedSessionKeyBase64) throws GeneralSecurityException {
        if (!StringUtils.hasLength(encryptedSessionKeyBase64)) {
            throw new IllegalArgumentException("Encrypted session key is required.");
        }
        Cipher rsaCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        return rsaCipher.doFinal(EncodingUtils.fromBase64(encryptedSessionKeyBase64));
    }

    /**
     * Encrypts the provided data using the AES session key from the request payload and returns a new RsaCipherPayload.
     *
     * @param data           the plaintext data to encrypt
     * @param requestPayload the RsaCipherPayload containing the encrypted AES key and IV
     * @return a new RsaCipherPayload containing the encrypted data
     * @throws GeneralSecurityException if a security exception occurs during encryption
     */
    public RsaCipherPayload encryptWithRequestPayload(String data, RsaCipherPayload requestPayload) throws GeneralSecurityException {
        if (requestPayload == null) {
            throw new IllegalArgumentException("Request payload cannot be null");
        }
        validatePayload(requestPayload);
        Cipher rsaCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        byte[] aesKeyBytes = rsaCipher.doFinal(EncodingUtils.fromBase64(requestPayload.encryptedAesKeyBase64()));
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, CryptoConstants.ALGORITHM_AES);
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);
        byte[] encryptedData = encryptWithAes(data, aesKey, iv);
        return new RsaCipherPayload(
                requestPayload.encryptedAesKeyBase64(),
                EncodingUtils.toBase64(iv),
                EncodingUtils.toBase64(encryptedData)
        );
    }

    /**
     * Validates the provided RsaCipherPayload to ensure that all required fields are present.
     *
     * @param payload the RsaCipherPayload to validate
     * @throws IllegalArgumentException if any required field is missing or invalid
     */
    private void validatePayload(RsaCipherPayload payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Payload cannot be null");
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

    /**
     * Decrypts the provided RsaCipherPayload using the provided AES session key.
     *
     * @param payload the RsaCipherPayload containing the encrypted data and IV
     * @param aesKey  the AES session key to use for decryption
     * @return the decrypted plaintext data as a String
     * @throws GeneralSecurityException if a security exception occurs during decryption
     */
    private String decryptWithAes(RsaCipherPayload payload, SecretKey aesKey) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(
                Cipher.DECRYPT_MODE,
                aesKey,
                new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, EncodingUtils.fromBase64(payload.ivBase64()))
        );
        byte[] plainBytes = aesCipher.doFinal(EncodingUtils.fromBase64(payload.encryptedDataBase64()));
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    /**
     * Encrypts the provided data using the provided AES session key and IV.
     *
     * @param data   the plaintext data to encrypt
     * @param aesKey the AES session key to use for encryption
     * @param iv     the initialization vector (IV) to use for encryption
     * @return the encrypted data as a byte array
     * @throws GeneralSecurityException if a security exception occurs during encryption
     */
    private byte[] encryptWithAes(String data, SecretKey aesKey, byte[] iv) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
        return aesCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }
}
