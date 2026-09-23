package com.example.demo.crypto.ecdh;

public record EcdhPublicKeyResponse(
        String algorithm,
        String curve,
        String ephemeralPublicKeyBase64,
        String identityPublicKeyBase64,
        String signatureAlgorithm,
        String signatureBase64
) {
}
