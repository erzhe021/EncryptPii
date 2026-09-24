package com.example.demo.crypto.ecdh;

/**
 * Represents the response containing the ephemeral ECDH public key and related information.
 *
 * @param ephemeralPublicKeyBase64 The base64-encoded ephemeral public key.
 * @param ecdsaPublicKeyBase64   The base64-encoded ECDSA public key.
 * @param signatureAlgorithm     The algorithm used for signing (e.g., "SHA256withECDSA").
 * @param signatureBase64        The base64-encoded signature of the ephemeral public key.
 */
public record EcdhPublicKeyResponse(
        String ephemeralPublicKeyBase64,
        String ecdsaPublicKeyBase64,
        String signatureAlgorithm,
        String signatureBase64
) {
}
