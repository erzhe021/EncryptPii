package com.example.demo.crypto.ecdh;

public record EcdhCipherPayload(
        String clientEphemeralPublicKeyBase64,
        String serverEphemeralPublicKeyBase64,
        String ivBase64,
        String encryptedDataBase64
) {
}
