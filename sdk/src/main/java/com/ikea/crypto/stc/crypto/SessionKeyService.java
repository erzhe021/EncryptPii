package com.ikea.crypto.stc.crypto;

import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.exception.InvalidCryptoRequestException;
import com.ikea.crypto.stc.util.EncodingUtils;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

/**
 * SessionKeyService provides utility methods for decrypting session keys that are encrypted using RSA.
 * <p>
 * This class is designed to handle the decryption of session keys that are transmitted in Base64 format.
 * It uses a provided RSA private key to perform the decryption and returns the resulting AES secret key.
 * </p>
 */
@Slf4j
public final class SessionKeyService {
    private SessionKeyService() {
    }

    public static SecretKey decryptSessionKeyBase64(String encryptedSessionKeyBase64, PrivateKey privateKey)
            throws GeneralSecurityException {
        log.debug("start to decrypt session key using RSA private key");
        byte[] encryptedSessionKey;
        try {
            encryptedSessionKey = EncodingUtils.fromBase64(encryptedSessionKeyBase64);
        } catch (IllegalArgumentException e) {
            throw new InvalidCryptoRequestException("Invalid Base64 format in encrypted session key.", e);
        }
        return decryptSessionKey(encryptedSessionKey, privateKey);
    }

    private static SecretKey decryptSessionKey(byte[] encryptedSessionKey, PrivateKey privateKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] sessionKey = cipher.doFinal(encryptedSessionKey);
        if (sessionKey.length != 16 && sessionKey.length != 24 && sessionKey.length != 32) {
            throw new InvalidCryptoRequestException("Invalid AES session key length.");
        }
        return new SecretKeySpec(sessionKey, CryptoConstants.ALGORITHM_AES);
    }
}
