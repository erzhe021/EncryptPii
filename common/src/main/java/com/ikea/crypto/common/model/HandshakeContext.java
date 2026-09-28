package com.ikea.crypto.common.model;

import jakarta.validation.constraints.NotBlank;

public record HandshakeContext(
        @NotBlank(message = "client ephemeral public key is required for ECDH encryption")
        String clientEphemeralPublicKeyBase64,

        @NotBlank(message = "server key ticket is required for ECDH encryption")
        String serverKeyTicketBase64
) {
}