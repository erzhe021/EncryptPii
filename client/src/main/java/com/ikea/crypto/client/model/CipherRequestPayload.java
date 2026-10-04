package com.ikea.crypto.client.model;

/**
 * CipherRequestPayload represents the encrypted request payload sent by the client.
 *
 * @param keyId                     Optional identifier of the server public key used to encrypt the session key.
 * @param encryptedSessionKeyBase64 The AES session key encrypted with the server's public key.
 * @param ivBase64                  The IV used for AES-GCM encryption.
 * @param encryptedDataBase64       The ciphertext encrypted with the AES session key.
 */
public record CipherRequestPayload(String keyId,
                                   String encryptedSessionKeyBase64,
                                   String ivBase64,
                                   String encryptedDataBase64) {
}
