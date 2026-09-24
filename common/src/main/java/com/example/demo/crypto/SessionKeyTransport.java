package com.example.demo.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.net.http.HttpRequest;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

public record SessionKeyTransport(
        String sessionKeyBase64,
        String ivBase64) {

    public static SessionKeyTransport fromGeneratedKey(SecretKey sessionKey, byte[] iv, PublicKey serverPublicKey)
            throws GeneralSecurityException {
        if (sessionKey == null) {
            throw new IllegalArgumentException("sessionKey is required");
        }
        if (iv == null || iv.length == 0) {
            throw new IllegalArgumentException("iv is required");
        }

        if (serverPublicKey == null) {
            return new SessionKeyTransport(
                    EncodingUtils.toBase64(sessionKey.getEncoded()),
                    EncodingUtils.toBase64(iv)
            );
        }

        if (!CryptoConstants.ALGORITHM_RSA.equalsIgnoreCase(serverPublicKey.getAlgorithm())) {
            throw new IllegalArgumentException("Only RSA server public keys are supported for encrypting a session key before header transport.");
        }

        Cipher rsaCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        rsaCipher.init(Cipher.ENCRYPT_MODE, serverPublicKey);
        byte[] encryptedSessionKey = rsaCipher.doFinal(sessionKey.getEncoded());

        return new SessionKeyTransport(
                EncodingUtils.toBase64(encryptedSessionKey),
                EncodingUtils.toBase64(iv)
        );
    }

    public HttpRequest.Builder apply(HttpRequest.Builder requestBuilder) {
        return requestBuilder
                .header(CryptoConstants.HEADER_CLIENT_SESSION_KEY, sessionKeyBase64)
                .header(CryptoConstants.HEADER_CLIENT_SESSION_IV, ivBase64);
    }
}
