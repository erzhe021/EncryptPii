package com.ikea.crypto.stc.model;

/**
 * Internal encrypted request material. On the wire, only {@code ivBase64} and
 * {@code encryptedDataBase64} are in the JSON body; key metadata and the wrapped
 * session key are transported separately in STC headers.
 *
 * @param keyId                     Optional identifier of the server public key used to encrypt the session key.
 * @param encryptedSessionKeyBase64 The AES session key encrypted with the server's public key.
 * @param ivBase64                  The IV used for AES-GCM encryption.
 * @param encryptedDataBase64       The ciphertext encrypted with the AES session key.
 */
public record CipherRequestPayload(
        String keyId,
        String encryptedSessionKeyBase64,
        String ivBase64,
        String encryptedDataBase64
) {
    public CipherRequestPayload(String encryptedSessionKeyBase64, String ivBase64, String encryptedDataBase64) {
        this(null, encryptedSessionKeyBase64, ivBase64, encryptedDataBase64);
    }
}
