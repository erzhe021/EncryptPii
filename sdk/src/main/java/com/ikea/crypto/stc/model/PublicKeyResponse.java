package com.ikea.crypto.stc.model;

import java.io.Serializable;

public record PublicKeyResponse(
        String publicKeyBase64,
        String keyId,
        long expiresAtEpochMillis,
        long refreshAtEpochMillis //Timestamp at which clients should fetch a replacement key
) implements Serializable {
}
