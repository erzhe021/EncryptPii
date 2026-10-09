package com.ikea.crypto.stc.model;

public record PublicKeyResponse(
        String publicKeyBase64,
        String keyId,
        long expiresAtEpochMillis,
        /** Timestamp at which clients should fetch a replacement key. */
        long refreshAtEpochMillis
) {
}
