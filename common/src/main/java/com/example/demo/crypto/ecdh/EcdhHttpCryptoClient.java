package com.example.demo.crypto.ecdh;

import com.example.demo.crypto.PublicKeyProvider;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;

/**
 * EcdhHttpCryptoClient is a client that fetches the server's ECDH public key over HTTP.
 * It implements the PublicKeyProvider interface, allowing it to be used in cryptographic operations
 * that require the server's public key.
 */
public class EcdhHttpCryptoClient implements PublicKeyProvider {
    private final HttpClient httpClient;
    private final URI serverBaseUri;
    private final ObjectMapper objectMapper;
    private final String publicKeyEndpoint;

    public EcdhHttpCryptoClient(URI serverBaseUri) {
        this(serverBaseUri, "/crypto/server/ecdh/public-key");
    }

    public EcdhHttpCryptoClient(URI serverBaseUri, String publicKeyEndpoint) {
        this.httpClient = HttpClient.newHttpClient();
        this.serverBaseUri = serverBaseUri;
        this.objectMapper = new ObjectMapper();
        this.publicKeyEndpoint = publicKeyEndpoint == null || publicKeyEndpoint.isBlank()
                ? "/crypto/server/ecdh/public-key"
                : publicKeyEndpoint;
    }

    @Override
    public Object fetchServerPublicKey() throws GeneralSecurityException {
        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve(publicKeyEndpoint))
                .GET()
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new GeneralSecurityException("Failed to fetch ECDH public key, status=" + response.statusCode());
            }
            return objectMapper.readValue(response.body(), EcdhPublicKeyResponse.class);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new GeneralSecurityException("Failed to fetch ECDH public key", e);
        }
    }

}
