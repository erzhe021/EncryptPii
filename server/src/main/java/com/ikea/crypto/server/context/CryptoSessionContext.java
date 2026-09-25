package com.ikea.crypto.server.context;

import com.ikea.crypto.common.rsa.SessionKeyTransport;
import com.ikea.crypto.common.ecdh.EcdhCipherPayload;
import com.ikea.crypto.common.ecdh.EcdhHandshakeContext;
import com.ikea.crypto.common.rsa.RsaCipherPayload;
import com.ikea.crypto.server.model.CryptoAlgorithm;

/**
 * CryptoSessionContext holds the context of a cryptographic session, including the algorithm used,
 * and the request-specific key material for that algorithm.
 *
 * @param algorithm          The cryptographic algorithm used for the session.
 * @param requestKeyMaterial The key material associated with the request, typed per algorithm.
 * @param <T>                The concrete key material type for the current algorithm.
 */
public record CryptoSessionContext<T>(CryptoAlgorithm algorithm, T requestKeyMaterial) {

    public static final String REQUEST_CONTEXT_KEY = "crypto.session.context";

    public static CryptoSessionContext<RsaCipherPayload> rsa(RsaCipherPayload payload) {
        return new CryptoSessionContext<>(CryptoAlgorithm.RSA, payload);
    }

    public static CryptoSessionContext<SessionKeyTransport> rsaResponseOnly(SessionKeyTransport transport) {
        return new CryptoSessionContext<>(CryptoAlgorithm.RSA, transport);
    }

    public static CryptoSessionContext<EcdhCipherPayload> ecdh(EcdhCipherPayload payload) {
        return new CryptoSessionContext<>(CryptoAlgorithm.ECDH, payload);
    }

    public static CryptoSessionContext<EcdhHandshakeContext> ecdhResponseOnly(EcdhHandshakeContext context) {
        return new CryptoSessionContext<>(CryptoAlgorithm.ECDH, context);
    }

    public T requireKeyMaterial() {
        if (requestKeyMaterial == null) {
            throw new IllegalStateException("Crypto session key material is required for algorithm: " + algorithm);
        }
        return requestKeyMaterial;
    }
}
