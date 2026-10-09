package com.ikea.crypto.stc.constant;

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
    public static final int RSA_KEY_SIZE_BITS = 2048;
    public static final int GCM_TAG_LENGTH_BITS = 128;
    public static final int GCM_IV_LENGTH_BYTES = 12;

    // --- Header Names for Crypto Session Key Transport ---
    public static final String HEADER_SENSITIVE_TRANSPORT_CRYPTO_SESSION_KEY = "X-STC-Session-Key";
    public static final String HEADER_SENSITIVE_TRANSPORT_CRYPTO_KEY_ID = "X-STC-Key-Id";
    public static final String HEADER_SENSITIVE_TRANSPORT_CRYPTO_ENCRYPTED = "X-STC-Encrypted";
    public static final String KEY_EXPIRED_CODE = "KEY_EXPIRED";
    public static final String INVALID_KEY_CODE = "INVALID_KEY";
}
