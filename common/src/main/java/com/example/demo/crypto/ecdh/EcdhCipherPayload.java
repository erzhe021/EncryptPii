package com.example.demo.crypto.ecdh;

import com.example.demo.crypto.AesCipherPayload;

/**
 * ECDH cipher payload containing the client and server ephemeral public keys, initialization vector, and encrypted data.
 */
public record EcdhCipherPayload(
        //client ephemeral public key
        String clientEphemeralPublicKeyBase64,

        //server ephemeral public key
        String serverEphemeralPublicKeyBase64,

        //initialization vector for aes
        String ivBase64,

        //data encrypted with aes
        String encryptedDataBase64
) implements AesCipherPayload {
}
