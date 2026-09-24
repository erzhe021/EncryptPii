package com.example.demo.crypto.rsa;

import com.example.demo.crypto.PublicKeyProvider;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;

/**
 * RsaHttpCryptoClient is a client that fetches the server's RSA public key over HTTP.
 * It implements the PublicKeyProvider interface, allowing it to be used in cryptographic operations
 * that require the server's public key.
 */
public class RsaHttpCryptoClient implements PublicKeyProvider {
    private final HttpClient httpClient;
    private final URI serverBaseUri;
    private final ObjectMapper objectMapper;
    private final String publicKeyEndpoint;

    public RsaHttpCryptoClient(URI serverBaseUri) {
        this(serverBaseUri, "/crypto/server/rsa/public-key");
    }

    public RsaHttpCryptoClient(URI serverBaseUri, String publicKeyEndpoint) {
        this.httpClient = HttpClient.newHttpClient();
        this.serverBaseUri = serverBaseUri;
        this.objectMapper = new ObjectMapper();
        this.publicKeyEndpoint = publicKeyEndpoint == null || publicKeyEndpoint.isBlank()
                ? "/crypto/server/rsa/public-key"
                : publicKeyEndpoint;
    }

    /**
     * Fetches the server's RSA public key from the specified endpoint.
     *
     * @return An RsaPublicKeyResponse containing the server's RSA public key.
     * @throws GeneralSecurityException If there is an error fetching or parsing the public key.
     */
    @Override
    public Object fetchServerPublicKey() throws GeneralSecurityException {
        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve(publicKeyEndpoint))
                .GET()
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new GeneralSecurityException("Failed to fetch RSA public key, status=" + response.statusCode());
            }
            return objectMapper.readValue(response.body(), RsaPublicKeyResponse.class);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new GeneralSecurityException("Failed to fetch RSA public key", e);
        }
    }
}
