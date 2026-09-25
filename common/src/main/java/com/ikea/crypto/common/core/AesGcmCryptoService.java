package com.ikea.crypto.common.core;

import com.ikea.crypto.common.CryptoConstants;
import com.ikea.crypto.common.EncodingUtils;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * AesGcmCryptoService provides utility methods for AES-GCM encryption and decryption.
 * It supports encrypting and decrypting byte arrays and strings, as well as encoding/decoding to/from Base64.
 */
@Slf4j
public final class AesGcmCryptoService {
    private AesGcmCryptoService() {
    }

    /**
     * Encrypts the given data using AES-GCM with the provided session key and IV.
     *
     * @param data       The plaintext data to encrypt.
     * @param sessionKey The AES session key for encryption.
     * @param iv         The initialization vector (IV) for AES-GCM.
     * @return The encrypted byte array.
     * @throws GeneralSecurityException If encryption fails due to cryptographic errors.
     */
    public static byte[] encrypt(byte[] data, SecretKey sessionKey, byte[] iv) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
        return aesCipher.doFinal(data);
    }

    /**
     * Decrypts the given encrypted data using AES-GCM with the provided session key and IV.
     *
     * @param encryptedData The encrypted byte array to decrypt.
     * @param sessionKey    The AES session key for decryption.
     * @param iv            The initialization vector (IV) used during encryption.
     * @return The decrypted byte array.
     * @throws GeneralSecurityException If decryption fails due to cryptographic errors.
     */
    public static byte[] decrypt(byte[] encryptedData, SecretKey sessionKey, byte[] iv) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
        return aesCipher.doFinal(encryptedData);
    }

    /**
     * Encrypts the given plaintext string using AES-GCM and returns the result as a Base64-encoded string.
     *
     * @param plainText  The plaintext string to encrypt.
     * @param sessionKey The AES session key for encryption.
     * @param iv         The initialization vector (IV) for AES-GCM.
     * @return The Base64-encoded encrypted string.
     * @throws GeneralSecurityException If encryption fails due to cryptographic errors.
     */
    public static String encryptAsBase64(String plainText, SecretKey sessionKey, byte[] iv) throws GeneralSecurityException {
        log.info("start to encrypt data using AES session key");
        byte[] encrypted = encrypt(plainText.getBytes(StandardCharsets.UTF_8), sessionKey, iv);
        return EncodingUtils.toBase64(encrypted);
    }

    /**
     * Decrypts the given Base64-encoded encrypted string using AES-GCM and returns the result as a plaintext string.
     *
     * @param encryptedBase64 The Base64-encoded encrypted string to decrypt.
     * @param sessionKey      The AES session key for decryption.
     * @param ivBase64        The Base64-encoded initialization vector (IV) used during encryption.
     * @return The decrypted plaintext string.
     * @throws GeneralSecurityException If decryption fails due to cryptographic errors.
     */
    public static String decryptFromBase64(String encryptedBase64, SecretKey sessionKey, String ivBase64) throws GeneralSecurityException {
        log.info("start to decrypt data using AES session key");
        byte[] decrypted = decrypt(EncodingUtils.fromBase64(encryptedBase64), sessionKey, EncodingUtils.fromBase64(ivBase64));
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
