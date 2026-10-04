package com.ikea.crypto.client.model;

/**
 * CipherResponsePayload is a record that represents the payload of a cipher response.
 * It contains the initialization vector (IV) and the encrypted data, both encoded in Base64 format.
 *
 * @param ivBase64            The initialization vector (IV) used for encryption, encoded in Base64 format.
 * @param encryptedDataBase64 The encrypted data, encoded in Base64 format.
 */
public record CipherResponsePayload(
        String ivBase64,
        String encryptedDataBase64
) {
}
