package com.ikea.crypto.common.model;

public record CipherResponsePayload(
        String ivBase64,
        String encryptedDataBase64
) {
}
