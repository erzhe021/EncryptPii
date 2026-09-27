package com.ikea.crypto.common.core;

import com.ikea.crypto.common.CryptoConstants;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * CryptoSessionMaterialFactory provides utility methods for generating cryptographic session materials,
 * including AES session keys and initialization vectors (IVs).
 */
public final class CryptoSessionMaterialFactory {
    private CryptoSessionMaterialFactory() {
    }

    public static SecretKey generateAesKey(SecureRandom secureRandom) throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS, secureRandom);
        return keyGenerator.generateKey();
    }

    public static byte[] generateIv(SecureRandom secureRandom) {
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        return iv;
    }
}
