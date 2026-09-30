package com.ikea.crypto.client.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.client.model.DemoPlainRequest;
import com.ikea.crypto.client.model.DemoPlainResponse;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.CipherResponsePayload;
import com.ikea.crypto.stc.model.PublicKeyResponse;
import com.ikea.crypto.stc.model.SessionKeyTransport;
import com.ikea.crypto.stc.util.EncodingUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * CryptoHttpClient handles all HTTP communication with the crypto server,
 * including fetching/caching public keys and transmitting encrypted request/response payloads.
 */
@Slf4j
public class CryptoHttpClient {

    private final HttpClient httpClient;
    private final URI serverBaseUri;
    private final ObjectMapper objectMapper;
    private final String publicKeyEndpoint;

    // Cache the fetched RSA public key and its parsed PublicKey instance to avoid unnecessary network calls.
    private volatile CachedPublicKey cachedPublicKey;

    public record ServerKeyInfo(String keyId, PublicKey publicKey, long expiresAtEpochMillis) {
        boolean isValid() {
            return System.currentTimeMillis() < expiresAtEpochMillis;
        }
    }

    private record CachedPublicKey(String keyId, PublicKey publicKey, long expiresAtEpochMillis) {
        boolean isValid() {
            return System.currentTimeMillis() < expiresAtEpochMillis;
        }

        ServerKeyInfo toServerKeyInfo() {
            return new ServerKeyInfo(keyId, publicKey, expiresAtEpochMillis);
        }
    }

    public CryptoHttpClient(URI serverBaseUri, String publicKeyEndpoint) {
        this.httpClient = HttpClient.newHttpClient();
        this.serverBaseUri = serverBaseUri;
        this.objectMapper = new ObjectMapper();
        this.publicKeyEndpoint = publicKeyEndpoint;
    }

    /**
     * Fetches the server's RSA public key metadata, returning the cached instance if still valid.
     */
    public ServerKeyInfo fetchServerKeyInfo() throws GeneralSecurityException {
        CachedPublicKey currentCache = this.cachedPublicKey;
        if (currentCache != null) {
            if (currentCache.isValid()) {
                log.debug("use cached RSA public key which is still valid, keyId={}", currentCache.keyId());
                return currentCache.toServerKeyInfo();
            } else {
                log.warn("cached RSA public key is expired, keyId={}", currentCache.keyId());
            }
        }

        log.debug("start to fetching RSA public key from server");
        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve(publicKeyEndpoint))
                .GET()
                .build();
        try {
            log.debug("【call api】start to call server endpoint to fetch RSA public key");
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            ensureSuccess(response, publicKeyEndpoint);

            PublicKeyResponse keyResponse = objectMapper.readValue(response.body(), PublicKeyResponse.class);
            PublicKey parsedKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA).generatePublic(
                    new X509EncodedKeySpec(EncodingUtils.fromBase64(keyResponse.publicKeyBase64()))
            );
            this.cachedPublicKey = new CachedPublicKey(keyResponse.keyId(), parsedKey, keyResponse.expiresAtEpochMillis());
            log.info("fetched RSA public key from server, keyId={}, caching it for future use", keyResponse.keyId());
            return this.cachedPublicKey.toServerKeyInfo();
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new GeneralSecurityException("Failed to fetch RSA public key from server", e);
        }
    }

    /**
     * Fetches the server's RSA public key, returning the cached instance if still valid.
     */
    public PublicKey fetchServerPublicKey() throws GeneralSecurityException {
        return fetchServerKeyInfo().publicKey();
    }

    /**
     * Sends bidirectional encrypted request to the server, expecting an AesCipherPayload response.
     */
    public CipherResponsePayload postBidirectional(String path, CipherRequestPayload requestPayload) throws Exception {
        HttpResponse<String> response = sendJsonRequest(path, requestPayload);
        return objectMapper.readValue(response.body(), CipherResponsePayload.class);
    }

    /**
     * Sends request-only encrypted payload to the server, expecting a plaintext PlainResponse response.
     */
    public DemoPlainResponse postRequestOnly(String path, CipherRequestPayload requestPayload) throws Exception {
        HttpResponse<String> response = sendJsonRequest(path, requestPayload);
        return objectMapper.readValue(response.body(), DemoPlainResponse.class);
    }

    /**
     * Sends response-only request to the server with encrypted session key in header,
     * expecting an AesCipherPayload response.
     */
    public CipherResponsePayload postResponseOnly(
            String path, DemoPlainRequest request, SessionKeyTransport sessionTransport) throws Exception {
        HttpRequest httpRequest = buildSessionKeyRequest(serverBaseUri.resolve(path), request, sessionTransport);
        HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        ensureSuccess(response, path);
        return objectMapper.readValue(response.body(), CipherResponsePayload.class);
    }

    private HttpResponse<String> sendJsonRequest(String path, Object requestBody) throws Exception {
        log.debug("【call api】start to call server endpoint to send json request: {}", path);
        HttpRequest request = buildJsonRequest(serverBaseUri.resolve(path), requestBody);
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        ensureSuccess(response, path);
        return response;
    }

    private HttpRequest buildJsonRequest(URI endpoint, Object requestBody) throws JsonProcessingException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        if (requestBody == null) {
            return builder.POST(HttpRequest.BodyPublishers.noBody()).build();
        } else {
            return builder.POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestBody))).build();
        }
    }

    private HttpRequest buildSessionKeyRequest(
            URI endpoint, DemoPlainRequest request, SessionKeyTransport sessionKeyTransport)
            throws JsonProcessingException {

        HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        HttpRequest.Builder transportBuilder = sessionKeyTransport.apply(builder);

        if (request != null) {
            return transportBuilder.POST(HttpRequest.BodyPublishers.ofString(
                    objectMapper.writeValueAsString(request))).build();
        } else {
            return transportBuilder.POST(HttpRequest.BodyPublishers.noBody()).build();
        }
    }

    private void ensureSuccess(HttpResponse<String> response, String path) {
        if (response.statusCode() != 200) {
            throw new IllegalStateException("request path: " + path + " failed: status="
                    + response.statusCode() + ", body=" + response.body());
        }
    }
}
