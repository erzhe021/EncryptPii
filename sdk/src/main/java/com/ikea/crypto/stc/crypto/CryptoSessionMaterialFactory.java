package com.ikea.crypto.stc.crypto;

import com.ikea.crypto.stc.constant.CryptoConstants;

import java.security.SecureRandom;

public final class CryptoSessionMaterialFactory {
    private CryptoSessionMaterialFactory() {
    }

    public static byte[] generateIv(SecureRandom secureRandom) {
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        return iv;
    }
}
