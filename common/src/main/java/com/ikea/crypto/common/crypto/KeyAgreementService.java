package com.ikea.crypto.common.crypto;

import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.util.HkdfUtils;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

@Slf4j
public final class KeyAgreementService {
    private KeyAgreementService() {
    }

    public static SecretKey deriveAesKey(PrivateKey privateKey, PublicKey publicKey, byte[] iv, String hkdfInfo) throws GeneralSecurityException {
        byte[] sharedSecret = deriveSharedSecret(privateKey, publicKey);
        return deriveAesKey(sharedSecret, iv, hkdfInfo);
    }

    public static SecretKey deriveAesKey(byte[] sharedSecret, byte[] iv, String hkdfInfo) throws GeneralSecurityException {
        return HkdfUtils.deriveAesKey(
                sharedSecret,
                iv,
                hkdfInfo.getBytes(StandardCharsets.UTF_8),
                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
        );
    }

    public static byte[] deriveSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws GeneralSecurityException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

}
