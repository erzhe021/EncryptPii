package com.ikea.crypto.common.core;

import com.ikea.crypto.common.CryptoConstants;
import com.ikea.crypto.common.EncodingUtils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

public final class HybridCryptoSessionService {
    private HybridCryptoSessionService() {
    }

    public static SecretKey generateAesSessionKey(SecureRandom secureRandom) throws GeneralSecurityException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS, secureRandom);
        return keyGenerator.generateKey();
    }

    public static byte[] generateIv(SecureRandom secureRandom) {
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        return iv;
    }

    public static String toBase64(byte[] bytes) {
        return EncodingUtils.toBase64(bytes);
    }
}
