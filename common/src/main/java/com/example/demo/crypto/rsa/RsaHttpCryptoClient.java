package com.example.demo.crypto.rsa;

import com.example.demo.crypto.PublicKeyProvider;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;

public class RsaHttpCryptoClient implements PublicKeyProvider {
    private final HttpClient httpClient;
    private final URI serverBaseUri;
    private final ObjectMapper objectMapper;

    private static final String PUBLIC_KEY_ENDPOINT = "/api/crypto/rsa/public-key";
    private static final String DECRYPT_ENDPOINT = "/api/crypto/rsa/decrypt";

    public RsaHttpCryptoClient(URI serverBaseUri) {
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

    public String decryptEncryptedData(RsaCipherPayload payload) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve(DECRYPT_ENDPOINT))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload)))
                .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("Failed to decrypt RSA payload, status=" + response.statusCode());
        }
        return objectMapper.readValue(response.body(), RsaDecryptDataResponse.class).data();
    }

}
