package com.ikea.crypto.stc.model;

public record VerificationKeyResponse(
        String publicKeyBase64,
        String keyId,
        long expiresAtEpochMillis
) {
}
