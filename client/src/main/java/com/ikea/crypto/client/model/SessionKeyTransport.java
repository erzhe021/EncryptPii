package com.ikea.crypto.client.model;

import com.ikea.crypto.client.constant.CryptoConstants;
import com.ikea.crypto.client.crypto.SessionKeyService;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.net.http.HttpRequest;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

/**
 * SessionKeyTransport is a record that encapsulates the encrypted session key for secure transport in HTTP headers.
 * It provides methods to create an instance from a generated session key and to apply the session key to an HTTP request.
 *
 * The RSA-encrypted session key and key identifier are carried only in request headers.
 */
@Slf4j
public record SessionKeyTransport(String keyId, String encryptedSessionKeyBase64) {

    public SessionKeyTransport {
        if (keyId == null || keyId.isBlank()) {
            throw new IllegalArgumentException("keyId is required");
        }
        if (encryptedSessionKeyBase64 == null || encryptedSessionKeyBase64.isBlank()) {
            throw new IllegalArgumentException("encryptedSessionKeyBase64 is required");
        }
    }

    public static SessionKeyTransport fromGeneratedKey(String keyId, SecretKey sessionKey, PublicKey serverPublicKey)
            throws GeneralSecurityException {
        log.debug("start to build SessionKeyTransport from generated session key");

        if (sessionKey == null) {
            throw new IllegalArgumentException("sessionKey is required");
        }
        if (serverPublicKey == null) {
            throw new IllegalArgumentException("serverPublicKey is required");
        }

        if (!CryptoConstants.ALGORITHM_RSA.equalsIgnoreCase(serverPublicKey.getAlgorithm())) {
            throw new IllegalArgumentException(
                    "Only RSA server public keys are supported for encrypting a session key before header transport.");
        }

        return new SessionKeyTransport(
                keyId,
                SessionKeyService.encryptSessionKeyAsBase64(sessionKey, serverPublicKey)
        );
    }

    public HttpRequest.Builder apply(HttpRequest.Builder requestBuilder) {
        log.debug("start to apply SessionKeyTransport to HttpRequest");
        return requestBuilder
                .header(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_KEY_ID, keyId)
                .header(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_SESSION_KEY, encryptedSessionKeyBase64);
    }
}
