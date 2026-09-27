package com.ikea.crypto.client.ecdh;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.common.ecdh.EcdhEphemeralKeyResponse;
import com.ikea.crypto.common.ecdh.EcdsaVerificationKeyResponse;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;

/**
 * EcdhHttpCryptoClient fetches the server's ECDH ephemeral public key and long-lived ECDSA public key
 * over HTTP, using independent cache/TTL policies for each key type.
 */
@Slf4j
public class EcdhHttpClient {
    private final HttpClient httpClient;
    private final URI serverBaseUri;
    private final ObjectMapper objectMapper;
    private final String ephemeralPublicKeyEndpoint;
    private final String ecdsaPublicKeyEndpoint;
    private volatile EcdsaVerificationKeyResponse cachedEcdsaResponse;

    public EcdhHttpClient(URI serverBaseUri, String ephemeralPublicKeyEndpoint, String ecdsaPublicKeyEndpoint) {
        this.httpClient = HttpClient.newHttpClient();
        this.serverBaseUri = serverBaseUri;
        this.objectMapper = new ObjectMapper();
        this.ephemeralPublicKeyEndpoint = ephemeralPublicKeyEndpoint;
        this.ecdsaPublicKeyEndpoint = ecdsaPublicKeyEndpoint;
    }

    public EcdhEphemeralKeyResponse fetchEphemeralPublicKey() throws GeneralSecurityException {
        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve(ephemeralPublicKeyEndpoint))
                .GET()
                .build();
        try {
            log.debug("【call api】fetching ECDH ephemeral public key from server");
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new GeneralSecurityException("Failed to fetch ECDH ephemeral public key, status=" + response.statusCode());
            }
            return objectMapper.readValue(response.body(), EcdhEphemeralKeyResponse.class);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new GeneralSecurityException("Failed to fetch ECDH ephemeral public key", e);
        }
    }

    public EcdsaVerificationKeyResponse fetchEcdsaPublicKey() throws GeneralSecurityException {
        if (cachedEcdsaResponse != null && System.currentTimeMillis() < cachedEcdsaResponse.expiresAtEpochMillis()) {
            log.debug("use cached ECDSA public key which is still valid");
            return cachedEcdsaResponse;
        }

        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve(ecdsaPublicKeyEndpoint))
                .GET()
                .build();
        try {
            log.debug("【call api】fetching ECDSA public key from server");
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new GeneralSecurityException("Failed to fetch ECDSA public key, status=" + response.statusCode());
            }
            EcdsaVerificationKeyResponse fetched = objectMapper.readValue(response.body(), EcdsaVerificationKeyResponse.class);
            log.debug("fetched ECDSA public key from server, caching it for future use");
            cachedEcdsaResponse = fetched;
            return fetched;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new GeneralSecurityException("Failed to fetch ECDSA public key", e);
        }
    }

}
