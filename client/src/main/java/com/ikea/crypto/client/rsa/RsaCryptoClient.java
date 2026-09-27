package com.ikea.crypto.client.rsa;

import com.ikea.crypto.client.CryptoRequestContext;
import com.ikea.crypto.common.AesCipherPayload;
import com.ikea.crypto.common.CryptoConstants;
import com.ikea.crypto.common.EncodingUtils;
import com.ikea.crypto.common.core.AesGcmCryptoService;
import com.ikea.crypto.common.core.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.core.RsaSessionKeyService;
import com.ikea.crypto.common.rsa.RsaCipherPayload;
import com.ikea.crypto.common.rsa.RsaPublicKeyResponse;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

/**
 * RsaCryptoClient is a client-side implementation of RSA encryption and decryption.
 * It provides methods to encrypt and decrypt data using a hybrid RSA-AES encryption scheme.
 * The class fetches the server's RSA public key, generates a random AES session key,
 * encrypts the data with AES, and then encrypts the AES session key with the server's RSA public key.
 */
@Slf4j
public class RsaCryptoClient {
    private final RsaHttpClient rsaHttpClient;
    private final SecureRandom secureRandom;

    public RsaCryptoClient(RsaHttpClient rsaHttpClient) {
        this.rsaHttpClient = rsaHttpClient;
        this.secureRandom = new SecureRandom();
    }

    public record EncryptionResult(RsaCipherPayload payload, CryptoRequestContext context) {
    }

    /**
     * Encrypts the given data using a hybrid RSA-AES encryption scheme.
     * The data is encrypted with a randomly generated AES session key,
     * which is then encrypted with the server's RSA public key.
     *
     * @param data The plaintext data to encrypt.
     * @return An RsaCipherPayload containing the encrypted AES session key, IV, and encrypted data.
     * @throws GeneralSecurityException If encryption fails due to cryptographic errors.
     */
    public EncryptionResult encrypt(String data) throws GeneralSecurityException {

        PublicKey serverPublicKey = fetchServerPublicKey();

        // Generate a random AES session key
        log.debug("start to generate client session key");
        SecretKey sessionKey = CryptoSessionMaterialFactory.generateAesSessionKey(secureRandom);

        // Generate a random IV for AES encryption
        byte[] iv = CryptoSessionMaterialFactory.generateIv(secureRandom);

        // Encrypt the data with AES using the session key and IV
        String encryptedDataBase64 = AesGcmCryptoService.encryptAsBase64(data, sessionKey, iv);

        // Encrypt the AES session key with the server's RSA public key
        String encryptedSessionKeyBase64 = RsaSessionKeyService.encryptSessionKeyAsBase64(sessionKey, serverPublicKey);

        // Return the encrypted payload containing the encrypted session key, IV, and encrypted data
        log.debug("put session key in context for future decryption");
        return new EncryptionResult(
                new RsaCipherPayload(
                        encryptedSessionKeyBase64,
                        EncodingUtils.toBase64(iv),
                        encryptedDataBase64
                ),
                new CryptoRequestContext(
                        CryptoConstants.ALGORITHM_RSA,
                        UUID.randomUUID().toString(),
                        sessionKey,
                        iv,
                        null, // No client ephemeral private key for RSA
                        null // No server ephemeral public key for RSA
                )
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
    public String decrypt(AesCipherPayload payload, CryptoRequestContext context) throws GeneralSecurityException {
        log.debug("start to decrypt data using session key in context");
        if (payload == null) {
            throw new IllegalArgumentException("payload cannot be null");
        }
        if (context == null || context.sessionKey() == null) {
            throw new IllegalStateException("No session key available for local RSA decryption");
        }
        // Decrypt the data using AES with the provided session key and the payload IV
        return AesGcmCryptoService.decryptFromBase64(
                payload.encryptedDataBase64(),
                context.sessionKey(),
                payload.ivBase64());
    }

    public String decrypt(AesCipherPayload responsePayload, SecretKey sessionKey) throws GeneralSecurityException {
        return AesGcmCryptoService.decryptFromBase64(
                responsePayload.encryptedDataBase64(),
                sessionKey,
                responsePayload.ivBase64()
        );
    }

    public PublicKey fetchServerPublicKey() throws GeneralSecurityException {
        RsaPublicKeyResponse publicKeyResponse = rsaHttpClient.fetchServerPublicKey();
        return KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(publicKeyResponse.publicKeyBase64()))
        );
    }
}
