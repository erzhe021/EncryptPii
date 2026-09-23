package com.example.demo.crypto.rsa;

public record RsaPublicKeyResponse(
        String algorithm,
        String publicKeyBase64
) {
}
