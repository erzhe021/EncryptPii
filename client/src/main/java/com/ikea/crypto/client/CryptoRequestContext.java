package com.ikea.crypto.client;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * CryptoRequestContext is a record that holds the context for a cryptographic request.
 *
 * @param algorithm                 The algorithm used for encryption/decryption.
 * @param requestId                 The unique identifier for the request.
 * @param sessionKey                The session key used for encryption/decryption.
 * @param iv                        The initialization vector used for encryption/decryption.
 * @param clientEphemeralPrivateKey The client's ephemeral private key used for key exchange.
 * @param serverEphemeralPublicKey  The server's ephemeral public key used for key exchange.
 */
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
