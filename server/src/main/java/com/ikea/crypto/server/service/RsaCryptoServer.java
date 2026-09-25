package com.ikea.crypto.server.service;

import com.ikea.crypto.common.CryptoConstants;
import com.ikea.crypto.common.EncodingUtils;
import com.ikea.crypto.common.core.AesGcmCryptoService;
import com.ikea.crypto.common.core.RsaSessionKeyService;
import com.ikea.crypto.common.rsa.RsaCipherPayload;
import com.ikea.crypto.common.rsa.RsaPublicKeyResponse;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Path;
import java.security.*;

/**
 * RsaCryptoServer is responsible for handling RSA encryption and decryption operations.
 * It manages the RSA key pair and provides methods to encrypt and decrypt data using RSA and AES algorithms.
 */
@Slf4j
public record RsaCryptoServer(PrivateKey rsaPrivateKey, PublicKey rsaPublicKey) {

    /**
     * Returns the RSA public key in a response format suitable for clients.
     *
     * @return an instance of RsaPublicKeyResponse containing the Base64-encoded RSA public key
     */
    public RsaPublicKeyResponse getPublicKey() {
        return new RsaPublicKeyResponse(EncodingUtils.toBase64(rsaPublicKey.getEncoded()));
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
        log.info("Creating RsaCryptoServer from keyDirectory={}", keyDirectory);
        AbstractCryptoKeyService.ensureKeyDirectory(keyDirectory);
        KeyFactory rsaKeyFactory = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA);
        KeyPair rsaKeyPair = AbstractCryptoKeyService.loadOrCreateKeyPair(
                keyDirectory.resolve("rsa-private-key.pkcs8"),
                keyDirectory.resolve("rsa-public-key.x509"),
                rsaKeyFactory,
                generator -> generator.initialize(2048)
        );
        return new RsaCryptoServer(rsaKeyPair.getPrivate(), rsaKeyPair.getPublic());
    }

    /**
     * Decrypts the provided RsaCipherPayload using the RSA private key and AES session key.
     *
     * @param payload the RsaCipherPayload containing the encrypted data, IV, and encrypted session key
     * @return the decrypted plaintext data as a String
     * @throws GeneralSecurityException if a security exception occurs during decryption
     */
    public String decrypt(RsaCipherPayload payload) throws GeneralSecurityException {
        validatePayload(payload);
        SecretKey sessionKey = decryptSessionKeyToSecretKey(payload.encryptedSessionKeyBase64());
        CryptoSessionContextAccessor.setResolvedSessionKey(sessionKey);
        return decryptWithAes(payload, sessionKey);
    }

    /**
     * Decrypts the provided Base64-encoded encrypted AES session key using the RSA private key.
     *
     * @param encryptedSessionKeyBase64 the Base64-encoded encrypted AES session key
     * @return the decrypted AES session key as a byte array
     * @throws GeneralSecurityException if a security exception occurs during decryption
     */
    public byte[] decryptSessionKey(String encryptedSessionKeyBase64) throws GeneralSecurityException {
        return decryptSessionKeyToSecretKey(encryptedSessionKeyBase64).getEncoded();
    }

    public SecretKey decryptSessionKeyToSecretKey(String encryptedSessionKeyBase64) throws GeneralSecurityException {
        log.info("start to decrypt session key from encryptedSessionKeyBase64");
        if (!StringUtils.hasLength(encryptedSessionKeyBase64)) {
            throw new IllegalArgumentException("Encrypted session key is required.");
        }
        return RsaSessionKeyService.decryptSessionKeyBase64(encryptedSessionKeyBase64, rsaPrivateKey);
    }

    /**
     * Encrypts the provided data using the AES session key decrypted from the provided Base64-encoded encrypted session key.
     *
     * @param data                       the plaintext data to encrypt
     * @param encryptedSessionKeyBase64  the Base64-encoded encrypted AES session key
     * @return an RsaCipherPayload containing the encrypted data, IV, and encrypted session key
     * @throws GeneralSecurityException if a security exception occurs during encryption
     */
    public RsaCipherPayload encryptWithRequestSessionKey(String data, String encryptedSessionKeyBase64) throws GeneralSecurityException {
        log.info("start to encrypt data using AES session key decrypted from encryptedSessionKeyBase64");
        SecretKey sessionKey = CryptoSessionContextAccessor.getResolvedSessionKey();
        if (sessionKey == null) {
            sessionKey = decryptSessionKeyToSecretKey(encryptedSessionKeyBase64);
        }
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);
        String encryptedDataBase64 = AesGcmCryptoService.encryptAsBase64(data, sessionKey, iv);
        return new RsaCipherPayload(
                encryptedSessionKeyBase64,
                EncodingUtils.toBase64(iv),
                encryptedDataBase64
        );
    }

    /**
     * Validates the provided RsaCipherPayload to ensure that all required fields are present.
     *
     * @param payload the RsaCipherPayload to validate
     * @throws IllegalArgumentException if any required field is missing or invalid
     */
    public void validatePayload(RsaCipherPayload payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Payload cannot be null");
        }
        if (!StringUtils.hasLength(payload.encryptedSessionKeyBase64())) {
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
     * @param sessionKey  the AES session key to use for decryption
     * @return the decrypted plaintext data as a String
     * @throws GeneralSecurityException if a security exception occurs during decryption
     */
    private String decryptWithAes(RsaCipherPayload payload, SecretKey sessionKey) throws GeneralSecurityException {
        return AesGcmCryptoService.decryptFromBase64(
                payload.encryptedDataBase64(),
                sessionKey,
                payload.ivBase64()
        );
    }
}
