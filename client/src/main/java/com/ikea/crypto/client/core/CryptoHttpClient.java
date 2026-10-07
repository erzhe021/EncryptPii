package com.ikea.crypto.client.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.client.constant.CryptoConstants;
import com.ikea.crypto.client.model.*;
import com.ikea.crypto.client.util.DateUtils;
import com.ikea.crypto.client.util.EncodingUtils;
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

    public static final String KEY_EXPIRED_CODE = "KEY_EXPIRED";

    public static final class HttpStatusException extends IllegalStateException {
        private final int statusCode;
        private final String responseBody;

        private HttpStatusException(String path, int statusCode, String responseBody) {
            super("request path: " + path + " failed: status=" + statusCode + ", body=" + responseBody);
            this.statusCode = statusCode;
            this.responseBody = responseBody;
        }
    }

    private final HttpClient httpClient;
    private final URI serverBaseUri;
    private final ObjectMapper objectMapper;
    private final String publicKeyEndpoint;

    // Cache the fetched RSA public key and its parsed PublicKey instance to avoid unnecessary network calls.
    private volatile CachedPublicKey cachedPublicKey;

    public record ServerKeyInfo(String keyId, PublicKey publicKey, long expiresAtEpochMillis) {
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

    public CryptoHttpClient(URI serverBaseUri) {
        this(serverBaseUri, null);
    }

    /**
     * Fetches the server's RSA public key metadata, returning the cached instance if still valid.
     */
    public ServerKeyInfo fetchServerKeyInfo() throws GeneralSecurityException {
        if (publicKeyEndpoint == null) {
            throw new IllegalStateException("Public key endpoint is not configured");
        }
        CachedPublicKey currentCache = this.cachedPublicKey;
        if (currentCache != null) {
            if (currentCache.isValid()) {
                log.debug("use cached RSA public key which is still valid, keyId={}, expiresAt={}",
                        currentCache.keyId(),
                        DateUtils.toDate(currentCache.expiresAtEpochMillis()));
                return currentCache.toServerKeyInfo();
            } else {
                log.warn("cached RSA public key is expired, keyId={}, expiresAt={}",
                        currentCache.keyId(),
                        DateUtils.toDate(currentCache.expiresAtEpochMillis()));
            }
        } else {
            log.debug("no cached RSA public key found");
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
            return cacheServerKeyInfo(keyResponse);
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new GeneralSecurityException("Failed to fetch RSA public key from server", e);
        }
    }

    /**
     * Extracts and caches the latest public key included in the plugin's KEY_EXPIRED response.
     */
    public ServerKeyInfo getRefreshedKeyFromFailure(Throwable failure) throws GeneralSecurityException {
        if (!(failure instanceof HttpStatusException httpFailure)
                || httpFailure.statusCode != 400) {
            return null;
        }
        JsonNode body;
        try {
            body = objectMapper.readTree(httpFailure.responseBody);
        } catch (JsonProcessingException e) {
            return null;
        }
        if (body == null || !KEY_EXPIRED_CODE.equals(body.path("code").asText())) {
            return null;
        }
        try {
            PublicKeyResponse keyResponse = objectMapper.treeToValue(body.path("data"), PublicKeyResponse.class);
            if (keyResponse.publicKeyBase64() == null || keyResponse.publicKeyBase64().isBlank()
                    || keyResponse.keyId() == null || keyResponse.keyId().isBlank()
                    || keyResponse.expiresAtEpochMillis() <= System.currentTimeMillis()) {
                throw new GeneralSecurityException("KEY_EXPIRED response contains invalid public key data");
            }
            log.warn("server returned KEY_EXPIRED response, refreshing cached RSA public key, keyId={}, expiresAt={}",
                    keyResponse.keyId(), DateUtils.toDate(keyResponse.expiresAtEpochMillis()));
            return cacheServerKeyInfo(keyResponse);
        } catch (JsonProcessingException e) {
            throw new GeneralSecurityException("Unable to parse public key data from KEY_EXPIRED response", e);
        }
    }

    private ServerKeyInfo cacheServerKeyInfo(PublicKeyResponse keyResponse) throws GeneralSecurityException {
        if (keyResponse == null || keyResponse.publicKeyBase64() == null
                || keyResponse.publicKeyBase64().isBlank() || keyResponse.keyId() == null
                || keyResponse.keyId().isBlank()
                || keyResponse.expiresAtEpochMillis() <= System.currentTimeMillis()) {
            throw new GeneralSecurityException("Server returned invalid or expired public key data");
        }
        try {
            PublicKey parsedKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA).generatePublic(
                    new X509EncodedKeySpec(EncodingUtils.fromBase64(keyResponse.publicKeyBase64()))
            );
            this.cachedPublicKey = new CachedPublicKey(
                    keyResponse.keyId(), parsedKey, keyResponse.expiresAtEpochMillis());
            log.info("received RSA public key, keyId={}, expiresAt={}, caching it for future use", keyResponse.keyId(),
                    DateUtils.toDate(keyResponse.expiresAtEpochMillis()));
            return this.cachedPublicKey.toServerKeyInfo();
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new GeneralSecurityException("Invalid RSA public key received from server", e);
        }
    }

    /**
     * Sends bidirectional encrypted request to the server, expecting an AesCipherPayload response.
     */
    public CipherResponsePayload postBidirectional(
            String path, CipherRequestPayload requestPayload, SessionKeyTransport sessionKeyTransport) throws Exception {
        HttpResponse<String> response = sendJsonRequest(path, requestPayload, sessionKeyTransport);
        return objectMapper.readValue(response.body(), CipherResponsePayload.class);
    }

    /**
     * Sends request-only encrypted payload to the server, expecting a plaintext Result<DemoPlainResponse>.
     */
    public Result<DemoPlainResponse> postRequestOnly(
            String path, CipherRequestPayload requestPayload, SessionKeyTransport sessionKeyTransport) throws Exception {
        HttpResponse<String> response = sendJsonRequest(path, requestPayload, sessionKeyTransport);
        return objectMapper.readValue(response.body(), new TypeReference<>() {
        });
    }

    public Result<DemoPlainResponse> postPlain(String path, DemoPlainRequest request) throws Exception {
        HttpResponse<String> response = sendJsonRequest(path, request);
        return objectMapper.readValue(response.body(), new TypeReference<>() {
        });
    }

    /**
     * Sends response-only request to the server with encrypted session key in header,
     * expecting an AesCipherPayload response.
     */
    public CipherResponsePayload postResponseOnly(
            String path, DemoPlainRequest request, SessionKeyTransport sessionTransport) throws Exception {
        HttpRequest httpRequest = buildJsonRequest(serverBaseUri.resolve(path), request, sessionTransport);
        HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        ensureSuccess(response, path);
        return objectMapper.readValue(response.body(), CipherResponsePayload.class);
    }

    private HttpResponse<String> sendJsonRequest(String path, Object requestBody) throws Exception {
        return sendJsonRequest(path, requestBody, null);
    }

    private HttpResponse<String> sendJsonRequest(
            String path, Object requestBody, SessionKeyTransport sessionKeyTransport) throws Exception {
        log.debug("【call api】start to call server endpoint to send json request: {}", path);
        HttpRequest request = buildJsonRequest(serverBaseUri.resolve(path), requestBody, sessionKeyTransport);
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        ensureSuccess(response, path);
        return response;
    }

    private HttpRequest buildJsonRequest(URI endpoint, Object requestBody) throws JsonProcessingException {
        return buildJsonRequest(endpoint, requestBody, null);
    }

    private HttpRequest buildJsonRequest(
            URI endpoint, Object requestBody, SessionKeyTransport sessionKeyTransport)
            throws JsonProcessingException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(endpoint)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        HttpRequest.Builder requestBuilder = sessionKeyTransport == null
                ? builder : sessionKeyTransport.apply(builder);
        if (requestBody == null) {
            return requestBuilder.POST(HttpRequest.BodyPublishers.noBody()).build();
        }
        return requestBuilder.POST(HttpRequest.BodyPublishers.ofString(
                objectMapper.writeValueAsString(requestBody))).build();
    }

    private void ensureSuccess(HttpResponse<String> response, String path) {
        if (response.statusCode() != 200) {
            throw new HttpStatusException(path, response.statusCode(), response.body());
        }
    }
}
