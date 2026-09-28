package com.ikea.crypto.common.model;

/**
 * Cipher request payload containing the client and server ephemeral public keys, initialization vector, and encrypted data.
 */
public record CipherRequestPayload(
        HandshakeContext handshakeContext,
        CipherDataPayload cipherDataPayload
) {
}
