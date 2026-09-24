package com.example.demo.crypto.ecdh;

public record EcdhCipherPayload(
        //client ephemeral public key
        String clientEphemeralPublicKeyBase64,

        //server ephemeral public key
        String serverEphemeralPublicKeyBase64,

        //initialization vector for aes
        String ivBase64,

        //data encrypted with aes
        String encryptedDataBase64
) {
}
