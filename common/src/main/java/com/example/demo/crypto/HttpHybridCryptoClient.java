package com.example.demo.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;

public class HttpHybridCryptoClient implements PublicKeyProvider {
    private final HttpClient httpClient;
    private final URI serverBaseUri;
    private final ObjectMapper objectMapper;
    private final String keyAlgorithm;

    public HttpHybridCryptoClient(URI serverBaseUri) {
        this(serverBaseUri, CryptoConstants.ALGORITHM_RSA);
    }

    public HttpHybridCryptoClient(URI serverBaseUri, String keyAlgorithm) {
        this.httpClient = HttpClient.newHttpClient();
        this.serverBaseUri = serverBaseUri;
        this.objectMapper = new ObjectMapper();
        this.keyAlgorithm = keyAlgorithm;
    }

    @Override
    public PublicKeyResponse fetchServerPublicKey() throws GeneralSecurityException {
        HttpRequest request = HttpRequest.newBuilder(
                        serverBaseUri.resolve("/api/crypto/public-key?algorithm=" + keyAlgorithm))
                .GET()
                .build();
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new GeneralSecurityException("Failed to fetch public key, status=" + response.statusCode());
            }
            return objectMapper.readValue(response.body(), PublicKeyResponse.class);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new GeneralSecurityException("Failed to fetch public key", e);
        }
    }

    public String decryptEncryptedData(HybridCipherPayload payload) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve("/api/crypto/decrypt-data"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload)))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("Failed to decrypt data, status=" + response.statusCode());
        }
        return objectMapper.readValue(response.body(), DecryptDataResponse.class).data();
    }
}
