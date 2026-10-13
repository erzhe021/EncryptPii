package com.ikea.crypto.stc.session;

import com.ikea.crypto.stc.exception.InvalidCryptoRequestException;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.SessionKeyHeaders;

import java.util.Objects;

/**
 * Represents the context for a cryptographic session, including the request payload and session key headers.
 *
 * @param requestPayload   The payload for the cipher request, which may be null for response-only contexts.
 * @param sessionKeyHeaders The headers required for the session key request, which must not be null.
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
            throw new InvalidCryptoRequestException("Encrypted request payload is required for request decryption.");
        }
        return requestPayload;
    }
}
