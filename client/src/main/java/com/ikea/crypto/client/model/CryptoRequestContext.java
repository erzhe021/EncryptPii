package com.ikea.crypto.client.model;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * CryptoRequestContext is a record that holds the context for an ECDH cryptographic request.
 *
 * @param requestId                 The unique identifier for the request.
 * @param sessionKey                The session key used for request encryption.
 * @param iv                        The initialization vector used for request encryption.
 * @param clientEphemeralPrivateKey The client's ephemeral private key used for key exchange.
 * @param serverEphemeralPublicKey  The server's ephemeral public key used for key exchange.
 * @param sharedSecret              The raw ECDH shared secret negotiated between client and server.
 */
public record CryptoRequestContext(
        String requestId,
        SecretKey sessionKey,
        byte[] iv,
        PrivateKey clientEphemeralPrivateKey,
        PublicKey serverEphemeralPublicKey,
        byte[] sharedSecret
) {
}
