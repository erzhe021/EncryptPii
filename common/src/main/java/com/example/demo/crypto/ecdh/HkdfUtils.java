package com.example.demo.crypto.ecdh;

import com.example.demo.crypto.CryptoConstants;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

/**
 * HkdfUtils is a utility class that provides methods for deriving keys
 * using the HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
 * It includes a method to derive an AES key from a shared secret, salt, and info parameters.
 */
public final class HkdfUtils {
    private HkdfUtils() {
    }

    /**
     * Derives an AES key from the given shared secret, salt, and info parameters using HKDF.
     *
     * @param sharedSecret the shared secret
     * @param salt the salt value
     * @param info the info value
     * @param outputLength the desired length of the derived key
     * @return the derived AES key
     * @throws GeneralSecurityException if a cryptographic error occurs
     */
    public static byte[] deriveAesKey(byte[] sharedSecret, byte[] salt, byte[] info, int outputLength)
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
}
