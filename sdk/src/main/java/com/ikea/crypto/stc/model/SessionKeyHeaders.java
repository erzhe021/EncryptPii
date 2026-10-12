package com.ikea.crypto.stc.model;

import com.ikea.crypto.stc.exception.InvalidCryptoPayloadException;

public record SessionKeyHeaders(String keyId, String encryptedSessionKeyBase64) {

    public SessionKeyHeaders {
        if (keyId == null || keyId.isBlank()
                || encryptedSessionKeyBase64 == null || encryptedSessionKeyBase64.isBlank()) {
            throw new InvalidCryptoPayloadException(
                    "X-STC-Key-Id and X-STC-Session-Key headers are required; body key transport is unsupported");
        }
    }
}
