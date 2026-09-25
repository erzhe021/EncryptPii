package com.example.demo.crypto.ecdh;

/**
 * EcdhHandshakeContext holds the context of an ECDH handshake, including the client's and server's ephemeral public keys.
 *
 * @param clientEphemeralPublicKeyBase64 The client's ephemeral public key in Base64 encoding.
 * @param serverEphemeralPublicKeyBase64 The server's ephemeral public key in Base64 encoding.
 */
public record EcdhHandshakeContext(String clientEphemeralPublicKeyBase64,
                                   String serverEphemeralPublicKeyBase64) {
}