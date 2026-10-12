package com.ikea.crypto.stc.crypto;

import com.ikea.crypto.stc.constant.CryptoConstants;

import java.security.SecureRandom;

public final class GcmIvGenerator {

    private static final SecureRandom secureRandom = new SecureRandom();

    private GcmIvGenerator() {
    }

    public static byte[] generateIv() {
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        return iv;
    }
}
