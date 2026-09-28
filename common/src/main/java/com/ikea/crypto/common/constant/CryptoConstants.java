package com.ikea.crypto.common.constant;

public final class CryptoConstants {
    private CryptoConstants() {
    }

    // --- Core Algorithms ---
    public static final String ALGORITHM_RSA = "RSA";
    public static final String ALGORITHM_AES = "AES";

    // --- Cipher Transformations ---
    public static final String TRANSFORMATION_RSA = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String TRANSFORMATION_AES = "AES/GCM/NoPadding";

    // --- Key Sizes & Lengths ---
    public static final int AES_KEY_SIZE_BITS = 256;
    public static final int GCM_TAG_LENGTH_BITS = 128;
    public static final int GCM_IV_LENGTH_BYTES = 12;

    // --- Header Names for Encrypted Session Key Transport ---
    public static final String HEADER_ENCRYPTED_SESSION_KEY = "X-Encrypted-Session-Key";
    public static final String HEADER_KEY_ID = "X-Crypto-Key-Id";
}
