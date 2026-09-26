package com.ikea.crypto.common.ecdh;

import jakarta.validation.constraints.NotBlank;

/**
 * EcdhHandshakeContext holds the context of an ECDH handshake, including the client's and server's ephemeral public keys.
 *
 * @param clientEphemeralPublicKeyBase64 The client's ephemeral public key in Base64 encoding.
 * @param serverEphemeralPublicKeyBase64 The server's ephemeral public key in Base64 encoding.
 */
public record EcdhHandshakeContext(
        @NotBlank(message = "client ephemeral public key is required for response-only ECDH encryption")
        String clientEphemeralPublicKeyBase64,

        @NotBlank(message = "server ephemeral public key is required for response-only ECDH encryption")
        String serverEphemeralPublicKeyBase64
) {
}