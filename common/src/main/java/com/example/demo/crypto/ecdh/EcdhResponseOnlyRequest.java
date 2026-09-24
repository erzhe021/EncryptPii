package com.example.demo.crypto.ecdh;

public record EcdhResponseOnlyRequest(
        String data,
        String clientEphemeralPublicKeyBase64,
        String serverEphemeralPublicKeyBase64
) {
}
