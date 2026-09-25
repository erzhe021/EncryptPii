package com.ikea.crypto.common.ecdh;

import com.ikea.crypto.common.CryptoConstants;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

@Slf4j
public final class EcdhKeyAgreementService {
    private EcdhKeyAgreementService() {
    }

    public static SecretKey deriveAesKey(PrivateKey privateKey, PublicKey publicKey, byte[] iv, String hkdfInfo) throws GeneralSecurityException {
        byte[] sharedSecret = deriveSharedSecret(privateKey, publicKey);
        return deriveAesKey(sharedSecret, iv, hkdfInfo);
    }

    private static byte[] deriveSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws GeneralSecurityException {
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
}
