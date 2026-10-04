package com.ikea.crypto.client.crypto;

import com.ikea.crypto.client.constant.CryptoConstants;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class CryptoSessionMaterialFactory {
    private CryptoSessionMaterialFactory() {
    }

    public static SecretKey generateAesKey(SecureRandom secureRandom) throws NoSuchAlgorithmException {
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
