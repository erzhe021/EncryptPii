package com.ikea.crypto.common.ecdh;

import jakarta.validation.constraints.NotBlank;

/**
 * HTTP request object for ECDH response-only operations.
 * It is intentionally an API-level DTO; conversion to protocol/session context happens in the controller/service layer.
 */
public record EcdhResponseOnlyRequest(

        //The plain data to be sent in the request. This can be null if no data is being sent.
        String data,

        @NotBlank(message = "client ephemeral public key is required for response-only ECDH encryption")
        String clientEphemeralPublicKeyBase64,

        @NotBlank(message = "server ephemeral public key is required for response-only ECDH encryption")
        String serverEphemeralPublicKeyBase64
) {

    public EcdhHandshakeContext toHandshakeContext() {
        return new EcdhHandshakeContext(clientEphemeralPublicKeyBase64, serverEphemeralPublicKeyBase64);
    }
}
