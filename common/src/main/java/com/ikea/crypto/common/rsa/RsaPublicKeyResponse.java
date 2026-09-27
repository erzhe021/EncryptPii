package com.ikea.crypto.common.rsa;

public record RsaPublicKeyResponse(
        String publicKeyBase64,
        String keyId,
        long expiresAtEpochMillis
) {
}
