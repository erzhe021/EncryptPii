package com.example.demo.crypto;

public record HybridCipherPayload(
        String algorithm,
        String encryptedAesKeyBase64,
        String clientEphemeralPublicKeyBase64,
        String ivBase64,
        String encryptedPhoneBase64
) {
}
