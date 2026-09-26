package com.ikea.crypto.common.ecdh;

/**
 * This class represents the payload for an ECDH (Elliptic Curve Diffie-Hellman) operation.
 * It contains the plain data to be sent in the request and the handshake context required for the ECDH operation.
 */
public record EcdhPlainPayload(

        //The handshake context containing the necessary information for the ECDH operation.
        EcdhHandshakeContext handshakeContext,

        //The plain data to be sent in the request. This can be null if no data is being sent.
        String data
) {
}
