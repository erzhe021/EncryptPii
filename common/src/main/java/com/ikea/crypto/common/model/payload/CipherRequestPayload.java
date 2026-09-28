package com.ikea.crypto.common.model.payload;

public record CipherRequestPayload(
        String encryptedSessionKeyBase64,
        String ivBase64,
        String encryptedDataBase64
) {
}
