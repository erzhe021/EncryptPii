package com.example.demo.crypto;

public record DefaultAesCipherPayload(
        String ivBase64,
        String encryptedDataBase64
) implements AesCipherPayload {
}
