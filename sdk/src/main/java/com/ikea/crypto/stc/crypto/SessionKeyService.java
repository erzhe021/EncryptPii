package com.ikea.crypto.stc.crypto;

import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.exception.InvalidCryptoPayloadException;
import com.ikea.crypto.stc.util.EncodingUtils;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

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
            throw new InvalidCryptoPayloadException("Invalid Base64 format in encrypted session key.", e);
        }
        return decryptSessionKey(encryptedSessionKey, privateKey);
    }

    private static SecretKey decryptSessionKey(byte[] encryptedSessionKey, PrivateKey privateKey)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] sessionKey = cipher.doFinal(encryptedSessionKey);
        if (sessionKey.length != 16 && sessionKey.length != 24 && sessionKey.length != 32) {
            throw new InvalidCryptoPayloadException("Invalid AES session key length.");
        }
        return new SecretKeySpec(sessionKey, CryptoConstants.ALGORITHM_AES);
    }
}
