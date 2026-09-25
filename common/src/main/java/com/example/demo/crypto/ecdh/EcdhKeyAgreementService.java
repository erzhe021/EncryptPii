package com.example.demo.crypto.ecdh;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.EncodingUtils;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

public final class EcdhKeyAgreementService {
    private EcdhKeyAgreementService() {
    }

    public static byte[] deriveSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws GeneralSecurityException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    public static SecretKey deriveAesKey(byte[] sharedSecret, byte[] iv, String hkdfInfo) throws GeneralSecurityException {
        byte[] derivedAesKey = HkdfUtils.deriveAesKey(
                sharedSecret,
                iv,
                hkdfInfo.getBytes(StandardCharsets.UTF_8),
                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
        );
        return new SecretKeySpec(derivedAesKey, CryptoConstants.ALGORITHM_AES);
    }

    public static String deriveAesKeyBase64(byte[] sharedSecret, byte[] iv, String hkdfInfo) throws GeneralSecurityException {
        return EncodingUtils.toBase64(deriveAesKey(sharedSecret, iv, hkdfInfo).getEncoded());
    }
}
