package com.example.demo.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;

public class EcdhHttpHybridCryptoClient implements PublicKeyProvider {
    private final HttpClient httpClient;
    private final URI serverBaseUri;
    private final ObjectMapper objectMapper;

    public EcdhHttpHybridCryptoClient(URI serverBaseUri) {
        this.httpClient = HttpClient.newHttpClient();
        this.serverBaseUri = serverBaseUri;
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public Object fetchServerPublicKey() throws GeneralSecurityException {
        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve("/api/crypto/ecdh/public-key"))
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

    public String decryptEncryptedData(EcdhHybridCipherPayload payload) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve("/api/crypto/ecdh/decrypt"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload)))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("Failed to decrypt ECDH payload, status=" + response.statusCode());
        }
        return objectMapper.readValue(response.body(), EcdhDecryptDataResponse.class).data();
    }

    public URI serverBaseUri() {
        return serverBaseUri;
    }
}
