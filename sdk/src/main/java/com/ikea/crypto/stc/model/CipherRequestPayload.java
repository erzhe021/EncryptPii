package com.ikea.crypto.stc.model;

/**
 * Encrypted request body. Key metadata and the wrapped session key are
 * transported separately in STC headers.
 *
 * @param ivBase64            The IV used for AES-GCM encryption.
 * @param encryptedDataBase64 The ciphertext encrypted with the AES session key.
 */
public record CipherRequestPayload(
        String ivBase64,
        String encryptedDataBase64
) {
}
