package com.ikea.crypto.common.model;

public record VerificationKeyResponse(
        String publicKeyBase64,
        String keyId,
        long expiresAtEpochMillis
) {
}
