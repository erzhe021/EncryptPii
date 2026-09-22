package com.example.demo.crypto;

public record RsaPublicKeyResponse(
        String algorithm,
        String publicKeyBase64
) {
}
