package com.ikea.crypto.common.util;

import com.ikea.crypto.common.constant.CryptoConstants;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public final class HkdfUtils {
    private HkdfUtils() {
    }

    private static byte[] deriveKey(byte[] sharedSecret, byte[] salt, byte[] info, int outputLength)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance(CryptoConstants.ALGORITHM_HMAC_SHA256);
        byte[] normalizedSalt = salt.length == 0 ? new byte[mac.getMacLength()] : salt;
        mac.init(new SecretKeySpec(normalizedSalt, CryptoConstants.ALGORITHM_HMAC_SHA256));
        byte[] pseudorandomKey = mac.doFinal(sharedSecret);

        byte[] result = new byte[outputLength];
        byte[] previousBlock = new byte[0];
        int generated = 0;
        int counter = 1;
        while (generated < outputLength) {
            mac.init(new SecretKeySpec(pseudorandomKey, CryptoConstants.ALGORITHM_HMAC_SHA256));
            mac.update(previousBlock);
            mac.update(info);
            mac.update((byte) counter);
            previousBlock = mac.doFinal();

            int copyLength = Math.min(previousBlock.length, outputLength - generated);
            System.arraycopy(previousBlock, 0, result, generated, copyLength);
            generated += copyLength;
            counter++;
        }
        return result;
    }

    public static SecretKey deriveAesKey(byte[] ikm, byte[] salt, byte[] info, int keyLengthBytes)
            throws GeneralSecurityException {
        byte[] keyBytes = deriveKey(ikm, salt, info, keyLengthBytes);
        return new SecretKeySpec(keyBytes, CryptoConstants.ALGORITHM_AES);
    }
}
