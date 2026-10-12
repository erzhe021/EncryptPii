package com.ikea.crypto.stc.session;

import com.ikea.crypto.stc.exception.InvalidCryptoPayloadException;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.SessionKeyHeaders;

import java.util.Objects;

/**
 * Crypto material associated with one HTTP request.
 */
public record CryptoSessionContext(CipherRequestPayload requestPayload, SessionKeyHeaders sessionKeyHeaders) {

    public CryptoSessionContext {
        Objects.requireNonNull(sessionKeyHeaders, "Session key headers are required");
    }

    public static CryptoSessionContext request(CipherRequestPayload payload, SessionKeyHeaders sessionKeyHeaders) {
        return new CryptoSessionContext(Objects.requireNonNull(payload, "Request payload is required"), sessionKeyHeaders);
    }

    public static CryptoSessionContext responseOnly(SessionKeyHeaders sessionKeyHeaders) {
        return new CryptoSessionContext(null, sessionKeyHeaders);
    }

    public CipherRequestPayload requireRequestPayload() {
        if (requestPayload == null) {
            throw new InvalidCryptoPayloadException("Encrypted request payload is required for request decryption");
        }
        return requestPayload;
    }
}
