package com.example.demo.crypto.ecdh;

/**
 * Request object for ECDH response-only operation.
 */
public record EcdhResponseOnlyRequest(

        //The plain data to be sent in the request. This can be null if no data is being sent.
        String data,

        //The client's ephemeral public key in Base64 encoding.
        String clientEphemeralPublicKeyBase64,

        //The server's ephemeral public key in Base64 encoding.
        String serverEphemeralPublicKeyBase64
) {
}
