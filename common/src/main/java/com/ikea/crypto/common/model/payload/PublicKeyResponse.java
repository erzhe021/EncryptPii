package com.ikea.crypto.common.model.payload;

public record PublicKeyResponse(
        String publicKeyBase64,
        String keyId,
        long expiresAtEpochMillis
) {
}
