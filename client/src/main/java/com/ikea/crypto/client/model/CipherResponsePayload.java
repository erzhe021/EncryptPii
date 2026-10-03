package com.ikea.crypto.client.model;

public record CipherResponsePayload(
        String ivBase64,
        String encryptedDataBase64
) {
}
