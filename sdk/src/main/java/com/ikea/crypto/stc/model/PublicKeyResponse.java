package com.ikea.crypto.stc.model;

import java.io.Serializable;

/**
 * Represents the response containing a public key, its identifier, and expiration information.
 *
 * @param publicKeyBase64      The public key encoded in Base64.
 * @param keyId                The identifier for the public key.
 * @param expiresAtEpochMillis The epoch time in milliseconds when the public key expires.
 * @param refreshAtEpochMillis The epoch time in milliseconds when clients should fetch a replacement key.
 */
public record PublicKeyResponse(
        String publicKeyBase64,
        String keyId,
        long expiresAtEpochMillis,
        long refreshAtEpochMillis //Timestamp at which clients should fetch a replacement key
) implements Serializable {
}
