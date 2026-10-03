package com.ikea.crypto.client.core;

import com.ikea.crypto.client.context.CryptoRequestContext;
import com.ikea.crypto.client.crypto.AesGcmCipher;
import com.ikea.crypto.client.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.client.crypto.SessionKeyService;
import com.ikea.crypto.client.model.CipherRequestPayload;
import com.ikea.crypto.client.model.CipherResponsePayload;
import com.ikea.crypto.client.util.EncodingUtils;
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

    public EncryptionResult encrypt(String data, PublicKey serverPublicKey) throws GeneralSecurityException {
        return encrypt(data, null, serverPublicKey);
    }

    public EncryptionResult encrypt(String data, String keyId, PublicKey serverPublicKey) throws GeneralSecurityException {
        if (serverPublicKey == null) {
            throw new IllegalArgumentException("serverPublicKey cannot be null");
        }

        // Generate a random AES session key
        log.debug("start to generate client session key");
        SecretKey sessionKey = CryptoSessionMaterialFactory.generateAesSessionKey(secureRandom);

        // Generate a random IV for AES encryption
        byte[] iv = CryptoSessionMaterialFactory.generateIv(secureRandom);

        // Encrypt the data with AES using the session key and IV
        String encryptedDataBase64 = AesGcmCipher.encryptAsBase64(data, sessionKey, iv);

        // Encrypt the AES session key with the server's RSA public key
        String encryptedSessionKeyBase64 = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, serverPublicKey);

        // Return the encrypted payload containing the encrypted session key, IV, and encrypted data
        log.debug("put session key in context for future decryption");
        return new EncryptionResult(
                new CipherRequestPayload(
                        keyId,
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

    public String decrypt(CipherResponsePayload payload, CryptoRequestContext context) throws GeneralSecurityException {
        log.debug("start to decrypt data using session key in context");
        if (payload == null) {
            throw new IllegalArgumentException("payload cannot be null");
        }
        if (context == null || context.sessionKey() == null) {
            throw new IllegalStateException("No session key available in context for decryption");
        }
        return AesGcmCipher.decryptFromBase64(
                payload.encryptedDataBase64(),
                context.sessionKey(),
                payload.ivBase64()
        );
    }

    public String decrypt(CipherResponsePayload responsePayload, SecretKey sessionKey) throws GeneralSecurityException {
        if (responsePayload == null) {
            throw new IllegalArgumentException("responsePayload cannot be null");
        }
        if (sessionKey == null) {
            throw new IllegalArgumentException("sessionKey cannot be null");
        }
        return AesGcmCipher.decryptFromBase64(
                responsePayload.encryptedDataBase64(),
                sessionKey,
                responsePayload.ivBase64()
        );
    }
}
