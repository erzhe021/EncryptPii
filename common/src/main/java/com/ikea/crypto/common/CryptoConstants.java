package com.ikea.crypto.common;

public final class CryptoConstants {

    // --- Core Algorithms ---
    public static final String ALGORITHM_RSA = "RSA";
    public static final String ALGORITHM_AES = "AES";
    public static final String ALGORITHM_EC = "EC";
    public static final String ALGORITHM_ECDH = "ECDH";
    public static final String ALGORITHM_HMAC_SHA256 = "HmacSHA256";

    // -- Signature Algorithms ---
    public static final String SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA = "SHA256withECDSA";

    // --- Cipher Transformations ---
    public static final String TRANSFORMATION_RSA = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String TRANSFORMATION_AES = "AES/GCM/NoPadding";

    // --- Elliptic Curves ---
    public static final String CURVE_ECDH = "secp256r1";

    // --- Key Derivation (HKDF) Info/Context Strings ---
    public static final String HKDF_INFO_REQUEST_AES_KEY = "request-aes-key";
    public static final String HKDF_INFO_RESPONSE_AES_KEY = "response-aes-key";

    // --- Key Sizes & Lengths ---
    public static final int AES_KEY_SIZE_BITS = 256;
    public static final int GCM_TAG_LENGTH_BITS = 128;
    public static final int GCM_IV_LENGTH_BYTES = 12;

    // --- Header Names for Client Session Key Transport ---
    public static final String HEADER_CLIENT_SESSION_KEY = "X-Client-Session-Key";
    public static final String HEADER_CLIENT_SESSION_IV = "X-Client-Session-IV";

    private CryptoConstants() {
        // Prevent instantiation
    }
}
