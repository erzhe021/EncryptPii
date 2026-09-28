package com.ikea.crypto.common.crypto;

import com.ikea.crypto.common.constant.CryptoConstants;

import java.security.SecureRandom;

/**
 * CryptoSessionMaterialFactory is a utility class that provides methods for generating cryptographic session materials,
 * such as initialization vectors (IVs) for AES-GCM encryption.
 */
public final class CryptoSessionMaterialFactory {
    private CryptoSessionMaterialFactory() {
    }

    public static byte[] generateIv(SecureRandom secureRandom) {
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        return iv;
    }
}
