package com.ikea.crypto.server.context;

import com.ikea.crypto.common.model.payload.CipherRequestPayload;
import com.ikea.crypto.common.model.payload.SessionKeyTransport;
/**
 * Context for a crypto session, which can be used to store the request key material.
 */
public record CryptoSessionContext(Object requestKeyMaterial) {

    public static final String REQUEST_CONTEXT_KEY = "crypto.session.context";

    public static CryptoSessionContext request(CipherRequestPayload payload) {
        return new CryptoSessionContext(payload);
    }

    public static CryptoSessionContext responseOnly(SessionKeyTransport transport) {
        return new CryptoSessionContext(transport);
    }

    public Object requireKeyMaterial() {
        if (requestKeyMaterial == null) {
            throw new IllegalStateException("Crypto session key material is required");
        }
        return requestKeyMaterial;
    }
}
