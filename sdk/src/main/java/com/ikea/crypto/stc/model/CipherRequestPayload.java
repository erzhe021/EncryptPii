package com.ikea.crypto.stc.model;

/**
 * Represents the payload for a cipher request, containing the initialization vector (IV) and the encrypted data.
 *
 * @param ivBase64            The initialization vector (IV) encoded in Base64.
 * @param encryptedDataBase64 The encrypted data encoded in Base64.
 */
public record CipherRequestPayload(
        String ivBase64,
        String encryptedDataBase64
) {
}
