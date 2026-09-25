package com.example.demo.crypto;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

public record CryptoRequestContext(
        String algorithm,
        String requestId,
        SecretKey sessionKey,
        byte[] iv,
        PrivateKey clientEphemeralPrivateKey,
        PublicKey serverEphemeralPublicKey
) {
    public CryptoRequestContext {
        if (algorithm == null || algorithm.isBlank()) {
            throw new IllegalArgumentException("algorithm is required");
        }
    }
}
