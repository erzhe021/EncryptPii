package com.ikea.crypto.common.ecdh;

/**
 * Represents the long-lived ECDSA verification public key used to validate ECDH ephemeral key signatures.
 *
 * @param ecdsaPublicKeyBase64 The base64-encoded ECDSA public key.
 * @param keyId                Stable key identifier for cache validation and rotation.
 * @param expiresAtEpochMillis Expiration time for client-side caching.
 */
public record EcdsaVerificationKeyResponse(
        String ecdsaPublicKeyBase64,
        String keyId,
        long expiresAtEpochMillis
) {
}
