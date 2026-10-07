package com.ikea.crypto.client.context;

import com.ikea.crypto.client.model.SessionKeyTransport;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Objects;

/**
 * CryptoRequestContext is a record that holds the context for a cryptographic request.
 *
 * @param requestId  The unique identifier for the request.
 * @param sessionKey The session key used for encryption/decryption.
 * @param iv                 The initialization vector used for encryption/decryption.
 * @param sessionKeyTransport The RSA-wrapped session material sent in request headers.
 */
public record CryptoRequestContext(
            String requestId,
            SecretKey sessionKey,
            byte[] iv,
            SessionKeyTransport sessionKeyTransport
) {
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof CryptoRequestContext that)) {
            return false;
        }
        return Objects.equals(requestId, that.requestId)
                && Objects.equals(sessionKey, that.sessionKey)
                && Arrays.equals(iv, that.iv)
                && Objects.equals(sessionKeyTransport, that.sessionKeyTransport);
    }

    @Override
    public int hashCode() {
        int result = Objects.hashCode(requestId);
        result = 31 * result + Objects.hashCode(sessionKey);
        result = 31 * result + Arrays.hashCode(iv);
        result = 31 * result + Objects.hashCode(sessionKeyTransport);
        return result;
    }

    @Override
    public String toString() {
        return "CryptoRequestContext[requestId=" + requestId
                + ", sessionKey=" + sessionKey
                + ", iv=" + Arrays.toString(iv)
                + ", sessionKeyTransport=" + sessionKeyTransport + "]";
    }
}
