package com.ikea.crypto.server.context;

import com.ikea.crypto.common.model.HandshakeContext;

public record CryptoSessionContext(HandshakeContext handshakeContext) {

    public static final String REQUEST_CONTEXT_KEY = "crypto.session.context";

    public static CryptoSessionContext of(HandshakeContext handshakeContext) {
        return new CryptoSessionContext(handshakeContext);
    }
}
