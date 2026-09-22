package com.example.demo.crypto;

public record EcdhHybridCipherPayload(
        String algorithm,
        String clientEphemeralPublicKeyBase64,
        String serverEphemeralPublicKeyBase64,
        String ivBase64,
        String encryptedDataBase64
) {
}
