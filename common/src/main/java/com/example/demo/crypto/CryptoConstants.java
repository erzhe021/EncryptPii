package com.example.demo.crypto;

public final class CryptoConstants {

    // --- Core Algorithms ---
    public static final String ALGORITHM_RSA = "RSA";
    public static final String ALGORITHM_AES = "AES";
    public static final String ALGORITHM_EC = "EC";
    public static final String ALGORITHM_ECDH = "ECDH";
    public static final String ALGORITHM_HMAC_SHA256 = "HmacSHA256";
    public static final String ALGORITHM_HYBRID = "RSA-OAEP + AES-256-GCM";
    public static final String ALGORITHM_ECDH_HKDF_AES = "ECDH-P256 + HKDF-SHA256 + AES-256-GCM";

    // --- Cipher Transformations ---
    public static final String TRANSFORMATION_RSA = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String TRANSFORMATION_AES = "AES/GCM/NoPadding";

    // --- Elliptic Curves ---
    public static final String CURVE_ECDH = "secp256r1";

    // --- Key Sizes & Lengths ---
    public static final int AES_KEY_SIZE_BITS = 256;
    public static final int GCM_TAG_LENGTH_BITS = 128;
    public static final int GCM_IV_LENGTH_BYTES = 12;

    private CryptoConstants() {
        // Prevent instantiation
    }
}
