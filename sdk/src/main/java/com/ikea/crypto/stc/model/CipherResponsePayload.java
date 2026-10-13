package com.ikea.crypto.stc.model;

/**
 * Represents the payload for a cipher response, containing the initialization vector (IV) and the encrypted data.
 *
 * @param ivBase64            The initialization vector (IV) encoded in Base64.
 * @param encryptedDataBase64 The encrypted data encoded in Base64.
 */
public record CipherResponsePayload(
        String ivBase64,
        String encryptedDataBase64
) {
}
