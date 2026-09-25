package com.example.demo.crypto;

import com.example.demo.crypto.core.RsaSessionKeyService;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.net.http.HttpRequest;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

/**
 * SessionKeyTransport is a record that encapsulates the encrypted session key and initialization vector (IV)
 * for secure transport in HTTP headers. It provides methods to create an instance from a generated session key
 * and to apply the session key and IV to an HTTP request.
 */
@Slf4j
public record SessionKeyTransport(
        String encryptedSessionKeyBase64,
        String ivBase64) {

    public static SessionKeyTransport fromGeneratedKey(SecretKey sessionKey, byte[] iv, PublicKey serverPublicKey) throws GeneralSecurityException {

        log.info("start to build SessionKeyTransport from generated session key");

        if (sessionKey == null) {
            throw new IllegalArgumentException("sessionKey is required");
        }
        if (iv == null || iv.length == 0) {
            throw new IllegalArgumentException("iv is required");
        }
        if (serverPublicKey == null) {
            throw new IllegalArgumentException("serverPublicKey is required");
        }

        if (!CryptoConstants.ALGORITHM_RSA.equalsIgnoreCase(serverPublicKey.getAlgorithm())) {
            throw new IllegalArgumentException("Only RSA server public keys are supported for encrypting a session key before header transport.");
        }

        return new SessionKeyTransport(
                RsaSessionKeyService.encryptSessionKeyBase64(sessionKey, serverPublicKey),
                EncodingUtils.toBase64(iv)
        );
    }

    public HttpRequest.Builder apply(HttpRequest.Builder requestBuilder) {
        log.info("start to apply SessionKeyTransport to HttpRequest");
        return requestBuilder
                .header(CryptoConstants.HEADER_CLIENT_SESSION_KEY, encryptedSessionKeyBase64)
                .header(CryptoConstants.HEADER_CLIENT_SESSION_IV, ivBase64);
    }
}
