package com.example.demo.crypto;

import java.net.http.HttpRequest;
import java.security.PublicKey;

public record ClientPublicKeyTransport(String algorithm, String format, String publicKeyBase64) {
    public static final String HEADER_CLIENT_PUBLIC_KEY = "X-Client-Public-Key";
    public static final String HEADER_CLIENT_PUBLIC_KEY_ALGORITHM = "X-Client-Public-Key-Algorithm";
    public static final String HEADER_CLIENT_PUBLIC_KEY_FORMAT = "X-Client-Public-Key-Format";
    public static final String DEFAULT_PUBLIC_KEY_FORMAT = "X.509";

    public static ClientPublicKeyTransport fromPublicKey(PublicKey publicKey, String algorithm) {
        if (publicKey == null) {
            throw new IllegalArgumentException("publicKey is required");
        }
        return new ClientPublicKeyTransport(
                algorithm,
                DEFAULT_PUBLIC_KEY_FORMAT,
                EncodingUtils.toBase64(publicKey.getEncoded())
        );
    }

    public static ClientPublicKeyTransport fromHeaders(String publicKeyBase64, String algorithmHeader, String formatHeader) {
        if (publicKeyBase64 == null || publicKeyBase64.isBlank()) {
            throw new IllegalArgumentException("Client public key is required in header: " + HEADER_CLIENT_PUBLIC_KEY);
        }
        String resolvedAlgorithm = algorithmHeader == null || algorithmHeader.isBlank() ? "RSA" : algorithmHeader;
        String resolvedFormat = formatHeader == null || formatHeader.isBlank() ? DEFAULT_PUBLIC_KEY_FORMAT : formatHeader;
        return new ClientPublicKeyTransport(resolvedAlgorithm, resolvedFormat, publicKeyBase64);
    }

    public HttpRequest.Builder apply(HttpRequest.Builder requestBuilder) {
        return requestBuilder
                .header(HEADER_CLIENT_PUBLIC_KEY, publicKeyBase64)
                .header(HEADER_CLIENT_PUBLIC_KEY_ALGORITHM, algorithm)
                .header(HEADER_CLIENT_PUBLIC_KEY_FORMAT, format);
    }
}
