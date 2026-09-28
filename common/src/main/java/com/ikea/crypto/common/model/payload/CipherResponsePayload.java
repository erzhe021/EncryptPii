package com.ikea.crypto.common.model.payload;

public record CipherResponsePayload(
        String ivBase64,
        String encryptedDataBase64
) {
}
