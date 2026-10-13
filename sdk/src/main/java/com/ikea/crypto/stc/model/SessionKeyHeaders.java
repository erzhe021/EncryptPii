package com.ikea.crypto.stc.model;

import com.ikea.crypto.stc.exception.InvalidCryptoRequestException;

/**
 * Represents the headers required for a session key request, including the key ID and the encrypted session key.
 *
 * @param keyId                   The identifier for the cryptographic key used to encrypt the session key.
 * @param encryptedSessionKeyBase64 The encrypted session key encoded in Base64.
 */
public record SessionKeyHeaders(String keyId, String encryptedSessionKeyBase64) {

    public SessionKeyHeaders {
        if (keyId == null || keyId.isBlank()
                || encryptedSessionKeyBase64 == null || encryptedSessionKeyBase64.isBlank()) {
            throw new InvalidCryptoRequestException(
                    "X-STC-Key-Id and X-STC-Session-Key headers are required but was not provided.");
        }
    }
}
