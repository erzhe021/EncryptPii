package com.ikea.crypto.stc.model;

public record CipherResponsePayload(
        String ivBase64,
        String encryptedDataBase64
) {
}
