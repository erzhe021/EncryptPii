package com.ikea.crypto.common.ecdh;

/**
 * HTTP request object for ECDH response-only operations.
 * It is intentionally an API-level DTO; conversion to protocol/session context happens in the controller/service layer.
 */
public record EcdhResponseOnlyRequest(

        //The plain data to be sent in the request. This can be null if no data is being sent.
        String data,

        //The client's ephemeral public key in Base64 encoding.
        String clientEphemeralPublicKeyBase64,

        //The server's ephemeral public key in Base64 encoding.
        String serverEphemeralPublicKeyBase64
) {

    public EcdhHandshakeContext toHandshakeContext() {
        return new EcdhHandshakeContext(clientEphemeralPublicKeyBase64, serverEphemeralPublicKeyBase64);
    }
}
