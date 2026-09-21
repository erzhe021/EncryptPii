package com.example.demo.crypto;

import java.util.Base64;

public final class EncodingUtils {
    private EncodingUtils() {
    }

    public static String toBase64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    public static byte[] fromBase64(String value) {
        return Base64.getDecoder().decode(value);
    }
}
