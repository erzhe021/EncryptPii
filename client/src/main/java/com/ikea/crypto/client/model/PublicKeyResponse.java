package com.ikea.crypto.client.model;

public record PublicKeyResponse(
        String publicKeyBase64,
        String keyId,
        long expiresAtEpochMillis
) {
}
