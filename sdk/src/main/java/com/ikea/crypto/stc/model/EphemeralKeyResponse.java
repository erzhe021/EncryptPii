package com.ikea.crypto.stc.model;

/**
 * Represents the server's short-lived ECDH ephemeral key material used for a single handshake.
 *
 * @param ephemeralPublicKeyBase64 The base64-encoded ephemeral public key.
 * @param signatureAlgorithm       The algorithm used for signing the ephemeral key.
 * @param signatureBase64          The base64-encoded signature of the ephemeral public key.
 * @param serverKeyTicketBase64    The stateless encrypted ticket containing the ephemeral private key and expiration.
 */
public record EphemeralKeyResponse(
        String ephemeralPublicKeyBase64,
        String signatureAlgorithm,
        String signatureBase64,
        String serverKeyTicketBase64
) {
}
