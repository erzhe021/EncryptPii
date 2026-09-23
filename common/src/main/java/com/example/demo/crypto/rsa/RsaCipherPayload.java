package com.example.demo.crypto.rsa;

public record RsaCipherPayload(
        String encryptedAesKeyBase64,
        String ivBase64,
        String encryptedDataBase64
) {
}
