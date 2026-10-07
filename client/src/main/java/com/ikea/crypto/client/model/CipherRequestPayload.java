package com.ikea.crypto.client.model;

/**
 * CipherRequestPayload represents the encrypted request payload sent by the client.
 *
 * @param ivBase64                  The IV used for AES-GCM encryption.
 * @param encryptedDataBase64       The ciphertext encrypted with the AES session key.
 */
public record CipherRequestPayload(String ivBase64,
                                   String encryptedDataBase64) {
}
