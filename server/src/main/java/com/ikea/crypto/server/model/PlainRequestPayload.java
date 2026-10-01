package com.ikea.crypto.server.model;

import com.ikea.crypto.stc.model.HandshakeContext;

/**
 * This class represents the payload for an ECDH (Elliptic Curve Diffie-Hellman) operation.
 * It contains the plain request to be sent in the request and the handshake context required for the ECDH operation.
 */
public record PlainRequestPayload(

        //The handshake context containing the necessary information for the ECDH operation.
        HandshakeContext handshakeContext,

        //The plain request to be sent in the request. This can be null if no request is being sent.
        DemoPlainRequest request
) {
}
