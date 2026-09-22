package com.example.demo.crypto;

public record RsaHybridCipherPayload(
        String algorithm,
        String encryptedAesKeyBase64,
        String ivBase64,
        String encryptedDataBase64
) {
}
