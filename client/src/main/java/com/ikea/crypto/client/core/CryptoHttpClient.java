package com.ikea.crypto.client.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.common.model.EphemeralKeyResponse;
import com.ikea.crypto.common.model.VerificationKeyResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * CryptoHttpClient handles all HTTP network communication with the remote Crypto Server.
 * It is responsible for:
 * 1. Fetching the server's ECDH ephemeral public key over HTTP.
 * 2. Fetching the server's long-lived ECDSA verification public key over HTTP with cache/TTL management.
 * 3. Sending JSON requests and payloads to crypto server endpoints.
 */
@Slf4j
public class CryptoHttpClient {
    private final HttpClient httpClient;
    private final URI serverBaseUri;
    private final ObjectMapper objectMapper;
    private final String ephemeralPublicKeyEndpoint;
    private final String ecdsaPublicKeyEndpoint;
    private volatile VerificationKeyResponse cachedEcdsaResponse;

    public CryptoHttpClient(URI serverBaseUri, String ephemeralPublicKeyEndpoint, String ecdsaPublicKeyEndpoint, ObjectMapper objectMapper) {
        this(HttpClient.newHttpClient(), serverBaseUri, objectMapper, ephemeralPublicKeyEndpoint, ecdsaPublicKeyEndpoint);
    }

    public CryptoHttpClient(HttpClient httpClient, URI serverBaseUri, ObjectMapper objectMapper, String ephemeralPublicKeyEndpoint, String ecdsaPublicKeyEndpoint) {
        this.httpClient = httpClient;
        this.serverBaseUri = serverBaseUri;
        this.objectMapper = objectMapper;
        this.ephemeralPublicKeyEndpoint = ephemeralPublicKeyEndpoint;
        this.ecdsaPublicKeyEndpoint = ecdsaPublicKeyEndpoint;
    }

    public EphemeralKeyResponse fetchEphemeralPublicKey() throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve(ephemeralPublicKeyEndpoint))
                .GET()
                .build();
        log.debug("【call api】fetching ECDH ephemeral public key from server");
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Failed to fetch ECDH ephemeral public key, status=" + response.statusCode());
        }
        return objectMapper.readValue(response.body(), EphemeralKeyResponse.class);
    }

    public VerificationKeyResponse fetchEcdsaPublicKey() throws IOException, InterruptedException {
        if (cachedEcdsaResponse != null && System.currentTimeMillis() < cachedEcdsaResponse.expiresAtEpochMillis()) {
            log.debug("use cached ECDSA public key which is still valid");
            return cachedEcdsaResponse;
        }

        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve(ecdsaPublicKeyEndpoint))
                .GET()
                .build();
        log.debug("【call api】fetching ECDSA public key from server");
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Failed to fetch ECDSA public key, status=" + response.statusCode());
        }
        VerificationKeyResponse fetched = objectMapper.readValue(response.body(), VerificationKeyResponse.class);
        log.debug("fetched ECDSA public key from server, caching it for future use");
        cachedEcdsaResponse = fetched;
        return fetched;
    }

    public HttpResponse<String> sendJsonRequest(String path, Object requestBody) throws IOException, InterruptedException {
        log.debug("【call api】start to call server endpoint to send json request: {}", path);
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(serverBaseUri.resolve(path))
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        if (requestBody == null) {
            requestBuilder.POST(HttpRequest.BodyPublishers.noBody());
        } else {
            requestBuilder.POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestBody)));
        }
        HttpResponse<String> response = httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("request path: " + path + " failed: status=" + response.statusCode() + ", body=" + response.body());
        }
        return response;
    }

    public <T> T post(String path, Object requestBody, Class<T> responseType) throws IOException, InterruptedException {
        HttpResponse<String> response = sendJsonRequest(path, requestBody);
        return objectMapper.readValue(response.body(), responseType);
    }

    public void clearEcdsaKeyCache() {
        this.cachedEcdsaResponse = null;
    }
}
