package com.ikea.crypto.common;

import java.util.Base64;

/**
 * EncodingUtils is a utility class that provides methods for encoding and decoding data.
 */
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
