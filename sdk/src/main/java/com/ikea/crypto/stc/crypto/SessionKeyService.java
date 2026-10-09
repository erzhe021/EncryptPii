package com.ikea.crypto.stc.crypto;

import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.util.EncodingUtils;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

@Slf4j
public final class SessionKeyService {
    private SessionKeyService() {
    }

    public static String encryptSessionKeyAsBase64(SecretKey sessionKey, PublicKey publicKey) throws GeneralSecurityException {
        log.debug("start to encrypt session key using RSA public key");
        return EncodingUtils.toBase64(encryptSessionKey(sessionKey, publicKey));
    }

    public static SecretKey decryptSessionKeyBase64(String encryptedSessionKeyBase64, PrivateKey privateKey) throws GeneralSecurityException {
        log.debug("start to decrypt session key using RSA private key");
        return decryptSessionKey(EncodingUtils.fromBase64(encryptedSessionKeyBase64), privateKey);
    }

    private static byte[] encryptSessionKey(SecretKey sessionKey, PublicKey publicKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(sessionKey.getEncoded());
    }

    private static SecretKey decryptSessionKey(byte[] encryptedSessionKey, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new SecretKeySpec(cipher.doFinal(encryptedSessionKey), CryptoConstants.ALGORITHM_AES);
    }
}
