package com.example.demo.crypto.ecdh;

import com.example.demo.crypto.PublicKeyProvider;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;

public class EcdhHttpCryptoClient implements PublicKeyProvider {
    private final HttpClient httpClient;
    private final URI serverBaseUri;
    private final ObjectMapper objectMapper;

    private static final String PUBLIC_KEY_ENDPOINT = "/api/crypto/ecdh/public-key";
    private static final String DECRYPT_ENDPOINT = "/api/crypto/ecdh/decrypt";

    public EcdhHttpCryptoClient(URI serverBaseUri) {
        this.httpClient = HttpClient.newHttpClient();
        this.serverBaseUri = serverBaseUri;
        this.objectMapper = new ObjectMapper();
    }

    @Override
    public Object fetchServerPublicKey() throws GeneralSecurityException {
        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve(PUBLIC_KEY_ENDPOINT))
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

    public String decryptEncryptedData(EcdhCipherPayload payload) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve(DECRYPT_ENDPOINT))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload)))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("Failed to decrypt ECDH payload, status=" + response.statusCode());
        }
        return objectMapper.readValue(response.body(), EcdhDecryptDataResponse.class).data();
    }

}
