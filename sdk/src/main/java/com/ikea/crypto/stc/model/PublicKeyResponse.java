package com.ikea.crypto.stc.model;

public record PublicKeyResponse(
        String publicKeyBase64,
        String keyId,
        long expiresAtEpochMillis
) {
}
