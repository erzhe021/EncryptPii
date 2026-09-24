package com.example.demo.crypto.ecdh;

public record EcdhContext(String clientEphemeralPublicKeyBase64,
                          String serverEphemeralPublicKeyBase64) {
}