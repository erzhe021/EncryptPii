package com.ikea.crypto.client.ecdh;

import com.ikea.crypto.client.PublicKeyProvider;
import com.ikea.crypto.common.ecdh.EcdhPublicKeyResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

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
@Slf4j
public class EcdhHttpClient implements PublicKeyProvider {
    private final HttpClient httpClient;
    private final URI serverBaseUri;
    private final ObjectMapper objectMapper;
    private final String publicKeyEndpoint;

    public EcdhHttpClient(URI serverBaseUri, String publicKeyEndpoint) {
        this.httpClient = HttpClient.newHttpClient();
        this.serverBaseUri = serverBaseUri;
        this.objectMapper = new ObjectMapper();
        this.publicKeyEndpoint = publicKeyEndpoint;
    }

    @Override
    public Object fetchServerPublicKey() throws GeneralSecurityException {
        log.info("start to fetching ECDH ephemeral public key and ECDSA public key from server");
        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve(publicKeyEndpoint))
                .GET()
                .build();
        try {
            log.info("start to call server endpoint to fetch ECDH ephemeral public key and ECDSA public key");
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new GeneralSecurityException(
                        "Failed to fetch ECDH ephemeral public key and ECDSA public key, status="
                                + response.statusCode());
            }
            return objectMapper.readValue(response.body(), EcdhPublicKeyResponse.class);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new GeneralSecurityException("Failed to fetch ECDH ephemeral public key and ECDSA public key", e);
        }
    }

}
