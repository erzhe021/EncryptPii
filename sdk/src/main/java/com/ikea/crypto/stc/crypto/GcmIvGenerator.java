package com.ikea.crypto.stc.crypto;

import com.ikea.crypto.stc.constant.CryptoConstants;

import java.security.SecureRandom;

/**
 * GcmIvGenerator is a utility class for generating random Initialization Vectors (IVs) for AES-GCM encryption.
 * <p>
 * This class provides a method to generate a secure random IV of the appropriate length for AES-GCM encryption.
 * </p>
 */
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
