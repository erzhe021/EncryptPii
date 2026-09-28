package com.ikea.crypto.client.core;

import com.ikea.crypto.client.context.CryptoRequestContext;
import com.ikea.crypto.common.crypto.AesGcmCryptoService;
import com.ikea.crypto.common.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.crypto.SessionKeyService;
import com.ikea.crypto.common.model.payload.CipherResponsePayload;
import com.ikea.crypto.common.model.payload.CipherRequestPayload;
import com.ikea.crypto.common.util.EncodingUtils;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * CryptoClient is a pure cryptographic engine responsible for in-memory hybrid RSA-AES encryption and decryption.
 * It contains no network/HTTP dependencies.
 */
@Slf4j
public class CryptoClient {

    private final SecureRandom secureRandom;

    public CryptoClient() {
        this.secureRandom = new SecureRandom();
    }

    public CryptoClient(SecureRandom secureRandom) {
        this.secureRandom = secureRandom == null ? new SecureRandom() : secureRandom;
    }

    public record EncryptionResult(CipherRequestPayload payload, CryptoRequestContext context) {
    }

    /**
     * Encrypts the given plaintext data using a hybrid RSA-AES encryption scheme with the provided server RSA public key.
     * The data is encrypted with a newly generated AES session key, which is encrypted with the server RSA public key.
     *
     * @param data            The plaintext string to encrypt.
     * @param serverPublicKey The server's RSA public key.
     * @return EncryptionResult containing the RsaCipherPayload and local CryptoRequestContext.
     * @throws GeneralSecurityException If cryptographic operations fail.
     */
    public EncryptionResult encrypt(String data, PublicKey serverPublicKey) throws GeneralSecurityException {
        if (serverPublicKey == null) {
            throw new IllegalArgumentException("serverPublicKey cannot be null");
        }

        // Generate a random AES session key
        log.debug("start to generate client session key");
        SecretKey sessionKey = CryptoSessionMaterialFactory.generateAesSessionKey(secureRandom);

        // Generate a random IV for AES encryption
        byte[] iv = CryptoSessionMaterialFactory.generateIv(secureRandom);

        // Encrypt the data with AES using the session key and IV
        String encryptedDataBase64 = AesGcmCryptoService.encryptAsBase64(data, sessionKey, iv);

        // Encrypt the AES session key with the server's RSA public key
        String encryptedSessionKeyBase64 = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, serverPublicKey);

        // Return the encrypted payload containing the encrypted session key, IV, and encrypted data
        log.debug("put session key in context for future decryption");
        return new EncryptionResult(
                new CipherRequestPayload(
                        encryptedSessionKeyBase64,
                        EncodingUtils.toBase64(iv),
                        encryptedDataBase64
                ),
                new CryptoRequestContext(
                        UUID.randomUUID().toString(),
                        sessionKey,
                        iv
                )
        );
    }

    /**
     * Decrypts the given AesCipherPayload using the session key stored in the request context.
     *
     * @param payload The encrypted response payload containing ciphertext and IV.
     * @param context The CryptoRequestContext containing the AES session key.
     * @return Decrypted plaintext string.
     * @throws GeneralSecurityException If decryption fails.
     */
    public String decrypt(CipherResponsePayload payload, CryptoRequestContext context) throws GeneralSecurityException {
        log.debug("start to decrypt data using session key in context");
        if (payload == null) {
            throw new IllegalArgumentException("payload cannot be null");
        }
        if (context == null || context.sessionKey() == null) {
            throw new IllegalStateException("No session key available in context for decryption");
        }
        return AesGcmCryptoService.decryptFromBase64(
                payload.encryptedDataBase64(),
                context.sessionKey(),
                payload.ivBase64()
        );
    }

    /**
     * Decrypts the given AesCipherPayload directly with an AES SecretKey.
     *
     * @param responsePayload The encrypted response payload containing ciphertext and IV.
     * @param sessionKey      The AES session key.
     * @return Decrypted plaintext string.
     * @throws GeneralSecurityException If decryption fails.
     */
    public String decrypt(CipherResponsePayload responsePayload, SecretKey sessionKey) throws GeneralSecurityException {
        if (responsePayload == null) {
            throw new IllegalArgumentException("responsePayload cannot be null");
        }
        if (sessionKey == null) {
            throw new IllegalArgumentException("sessionKey cannot be null");
        }
        return AesGcmCryptoService.decryptFromBase64(
                responsePayload.encryptedDataBase64(),
                sessionKey,
                responsePayload.ivBase64()
        );
    }
}
