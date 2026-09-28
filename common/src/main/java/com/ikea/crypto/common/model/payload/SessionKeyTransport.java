package com.ikea.crypto.common.model.payload;

import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.crypto.SessionKeyService;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.net.http.HttpRequest;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

/**
 * SessionKeyTransport is a record that encapsulates the encrypted session key for secure transport in HTTP headers.
 * It provides methods to create an instance from a generated session key and to apply the session key to an HTTP request.
 *
 * This record is only used in RSA response-only encryption, where the client sends a request without encryption,
 * and the server responds with encrypted data. The client provides the session key in the request headers,
 * and the server generates its own IV when encrypting the response.
 */
@Slf4j
public record SessionKeyTransport(String keyId, String encryptedSessionKeyBase64) {

    public SessionKeyTransport(String encryptedSessionKeyBase64) {
        this(null, encryptedSessionKeyBase64);
    }

    public static SessionKeyTransport fromGeneratedKey(SecretKey sessionKey, PublicKey serverPublicKey) throws GeneralSecurityException {
        return fromGeneratedKey(null, sessionKey, serverPublicKey);
    }

    public static SessionKeyTransport fromGeneratedKey(String keyId, SecretKey sessionKey, PublicKey serverPublicKey) throws GeneralSecurityException {
        log.debug("start to build SessionKeyTransport from generated session key");

        if (sessionKey == null) {
            throw new IllegalArgumentException("sessionKey is required");
        }
        if (serverPublicKey == null) {
            throw new IllegalArgumentException("serverPublicKey is required");
        }

        if (!CryptoConstants.ALGORITHM_RSA.equalsIgnoreCase(serverPublicKey.getAlgorithm())) {
            throw new IllegalArgumentException("Only RSA server public keys are supported for encrypting a session key before header transport.");
        }

        return new SessionKeyTransport(
                keyId,
                SessionKeyService.encryptSessionKeyAsBase64(sessionKey, serverPublicKey)
        );
    }

    public HttpRequest.Builder apply(HttpRequest.Builder requestBuilder) {
        log.debug("start to apply SessionKeyTransport to HttpRequest");
        HttpRequest.Builder builder = requestBuilder
                .header(CryptoConstants.HEADER_CRYPTO_SESSION_KEY, encryptedSessionKeyBase64);
        if (keyId != null && !keyId.isBlank()) {
            builder.header(CryptoConstants.HEADER_KEY_ID, keyId);
        }
        return builder;
    }
}
