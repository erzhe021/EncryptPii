package com.example.demo.crypto;

public record PublicKeyResponse(
        String algorithm,
        String curve,
        String publicKeyBase64
) {
}
