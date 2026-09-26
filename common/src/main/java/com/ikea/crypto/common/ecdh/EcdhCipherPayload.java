package com.ikea.crypto.common.ecdh;

import com.ikea.crypto.common.AesCipherPayload;

/**
 * ECDH cipher payload containing the client and server ephemeral public keys, initialization vector, and encrypted data.
 */
public record EcdhCipherPayload(
        EcdhHandshakeContext handshakeContext,
        AesCipherPayload aesCipherPayload
) {
}
