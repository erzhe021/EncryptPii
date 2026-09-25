package com.ikea.crypto.common.core;

import com.ikea.crypto.common.CryptoConstants;
import com.ikea.crypto.common.EncodingUtils;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * RsaSessionKeyService provides utility methods for encrypting and decrypting AES session keys using RSA public and private keys.
 * It supports both byte array and Base64-encoded string representations of the encrypted session key.
 */
@Slf4j
public final class RsaSessionKeyService {
    private RsaSessionKeyService() {
    }

    /**
     * Encrypts the given AES session key using the provided RSA public key.
     *
     * @param sessionKey The AES session key to encrypt.
     * @param publicKey  The RSA public key used for encryption.
     * @return The encrypted session key as a byte array.
     * @throws GeneralSecurityException If encryption fails due to cryptographic errors.
     */
    public static byte[] encryptSessionKey(SecretKey sessionKey, PublicKey publicKey) throws GeneralSecurityException {
        Cipher rsaCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return rsaCipher.doFinal(sessionKey.getEncoded());
    }

    /**
     * Decrypts the given AES session key using the provided RSA private key.
     *
     * @param encryptedSessionKey The encrypted AES session key as a byte array.
     * @param privateKey          The RSA private key used for decryption.
     * @return The decrypted AES session key.
     * @throws GeneralSecurityException If decryption fails due to cryptographic errors.
     */
    public static SecretKey decryptSessionKey(byte[] encryptedSessionKey, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher rsaCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new SecretKeySpec(rsaCipher.doFinal(encryptedSessionKey), CryptoConstants.ALGORITHM_AES);
    }

    /**
     * Encrypts the given AES session key using the provided RSA public key and encodes the result as a Base64 string.
     *
     * @param sessionKey The AES session key to encrypt.
     * @param publicKey  The RSA public key used for encryption.
     * @return The encrypted session key as a Base64-encoded string.
     * @throws GeneralSecurityException If encryption fails due to cryptographic errors.
     */
    public static String encryptSessionKeyBase64(SecretKey sessionKey, PublicKey publicKey) throws GeneralSecurityException {
        log.info("start to encrypt session key using RSA public key");
        return EncodingUtils.toBase64(encryptSessionKey(sessionKey, publicKey));
    }

    /**
     * Decrypts the given AES session key from a Base64-encoded string using the provided RSA private key.
     *
     * @param encryptedSessionKeyBase64 The encrypted AES session key as a Base64-encoded string.
     * @param privateKey                The RSA private key used for decryption.
     * @return The decrypted AES session key.
     * @throws GeneralSecurityException If decryption fails due to cryptographic errors.
     */
    public static SecretKey decryptSessionKeyBase64(String encryptedSessionKeyBase64, PrivateKey privateKey) throws GeneralSecurityException {
        log.info("start to decrypt session key using RSA private key");
        return decryptSessionKey(EncodingUtils.fromBase64(encryptedSessionKeyBase64), privateKey);
    }
}
