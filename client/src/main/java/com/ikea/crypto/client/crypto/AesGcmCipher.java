package com.ikea.crypto.client.crypto;

import com.ikea.crypto.client.constant.CryptoConstants;
import com.ikea.crypto.client.util.EncodingUtils;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

@Slf4j
public final class AesGcmCipher {
    private AesGcmCipher() {
    }

    public static byte[] encrypt(byte[] data, SecretKey secretKey, byte[] iv) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
        return aesCipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] encryptedData, SecretKey secretKey, byte[] iv) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
        return aesCipher.doFinal(encryptedData);
    }

    public static String encryptAsBase64(String plainText, SecretKey secretKey, byte[] iv) throws GeneralSecurityException {
        log.debug("start to encrypt data using secret key");
        byte[] encrypted = encrypt(plainText.getBytes(StandardCharsets.UTF_8), secretKey, iv);
        return EncodingUtils.toBase64(encrypted);
    }

    public static String decryptFromBase64(String encryptedBase64, SecretKey secretKey, String ivBase64) throws GeneralSecurityException {
        log.debug("start to decrypt data using secret key");
        byte[] decrypted = decrypt(EncodingUtils.fromBase64(encryptedBase64), secretKey, EncodingUtils.fromBase64(ivBase64));
        return new String(decrypted, StandardCharsets.UTF_8);
    }

}
