package com.example.demo.crypto;

public final class CryptoConstants {
    public static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    public static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
    public static final String ECDH_ALGORITHM = "EC";
    public static final String ECDH_CURVE = "secp256r1";
    public static final String ECDH_KEY_AGREEMENT = "ECDH";
    public static final String HMAC_SHA256 = "HmacSHA256";
    public static final int AES_KEY_SIZE_BITS = 256;
    public static final int GCM_TAG_LENGTH_BITS = 128;
    public static final int GCM_IV_LENGTH_BYTES = 12;

    private CryptoConstants() {
    }
}
