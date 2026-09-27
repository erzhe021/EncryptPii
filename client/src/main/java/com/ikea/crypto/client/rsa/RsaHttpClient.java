package com.ikea.crypto.client.rsa;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.common.rsa.RsaPublicKeyResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;

@Slf4j
public class RsaHttpClient {
    private final HttpClient httpClient;
    private final URI serverBaseUri;
    private final ObjectMapper objectMapper;
    private final String publicKeyEndpoint;
    // Cache the fetched RSA public key response to avoid unnecessary network calls.
    private volatile RsaPublicKeyResponse cachedResponse;

    public RsaHttpClient(URI serverBaseUri, String publicKeyEndpoint) {
        this.httpClient = HttpClient.newHttpClient();
        this.serverBaseUri = serverBaseUri;
        this.objectMapper = new ObjectMapper();
        this.publicKeyEndpoint = publicKeyEndpoint;
    }

    public RsaPublicKeyResponse fetchServerPublicKey() throws GeneralSecurityException {
        if (cachedResponse != null && System.currentTimeMillis() < cachedResponse.expiresAtEpochMillis()) {
            log.debug("use cached RSA public key which is still valid");
            return cachedResponse;
        }

        log.debug("start to fetching RSA public key from server");
        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve(publicKeyEndpoint))
                .GET()
                .build();
        try {
            log.debug("【call api】start to call server endpoint to fetch RSA public key");
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new GeneralSecurityException("Failed to fetch RSA public key, status=" + response.statusCode());
            }
            RsaPublicKeyResponse fetched = objectMapper.readValue(response.body(), RsaPublicKeyResponse.class);
            log.debug("fetched RSA public key from server, caching it for future use");
            cachedResponse = fetched;
            return fetched;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new GeneralSecurityException("Failed to fetch RSA public key", e);
        }
    }
}
