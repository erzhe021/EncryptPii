package com.example.demo.client;

import com.example.demo.crypto.AesCipherPayload;
import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.PlainData;
import com.example.demo.crypto.SessionKeyTransport;
import com.example.demo.crypto.core.AesGcmCryptoService;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;

/**
 * AbstractCryptoClientController provides common functionality for crypto client controllers.
 * It handles HTTP requests, JSON serialization/deserialization, and cryptographic operations.
 */
public abstract class AbstractCryptoClientController {

    protected final URI serverBaseUri;
    protected final HttpClient httpClient;
    protected final ObjectMapper objectMapper;

    protected AbstractCryptoClientController(String serverBaseUrl) {
        this.serverBaseUri = URI.create(serverBaseUrl);
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
    }

    private void validatePlainData(PlainData data) {
        if (data == null || data.data() == null || data.data().isEmpty()) {
            throw new IllegalArgumentException("PlainData cannot be null or empty");
        }
    }

    protected String toJsonString(PlainData data) throws Exception {
        validatePlainData(data);
        return objectMapper.writeValueAsString(data);
    }

    protected HttpResponse<String> sendJsonRequest(String path, Object requestBody) throws Exception {
        return httpClient.send(buildJsonRequest(serverBaseUri.resolve(path), requestBody), HttpResponse.BodyHandlers.ofString());
    }

    protected HttpResponse<String> sendJsonRequestWithSessionKeyTransport(String data, String path, SessionKeyTransport sessionTransport) throws Exception {
        return httpClient.send(
                buildSessionKeyRequest(serverBaseUri.resolve(path), data, sessionTransport),
                HttpResponse.BodyHandlers.ofString()
        );
    }

    private HttpRequest buildJsonRequest(URI endpoint, Object requestBody) throws Exception {
        if (requestBody == null) {
            return HttpRequest.newBuilder(endpoint)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
        } else {
            return HttpRequest.newBuilder(endpoint)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestBody)))
                    .build();
        }
    }

    private HttpRequest buildSessionKeyRequest(URI endpoint, String data, SessionKeyTransport sessionKeyTransport) throws Exception {
        if (data != null) {
            return sessionKeyTransport.apply(
                            HttpRequest.newBuilder(endpoint).header("Content-Type", "application/json")
                    )
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(new PlainData(data))))
                    .build();
        } else {
            return sessionKeyTransport.apply(
                            HttpRequest.newBuilder(endpoint).header("Content-Type", "application/json")
                    )
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
        }
    }

    protected void ensureSuccess(HttpResponse<String> response, String operation) {
        if (response.statusCode() != 200) {
            throw new IllegalStateException(operation + " request failed: status=" + response.statusCode() + ", body=" + response.body());
        }
    }

    protected SecretKey generateSessionKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        return keyGenerator.generateKey();
    }

    protected byte[] generateIv() {
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * Decrypts the response data using the provided AES session key and the response payload.
     *
     * @param responsePayload the response payload containing the encrypted data and IV
     * @param sessionKey      the AES session key used for decryption
     * @return the decrypted response data as a String
     * @throws Exception if an error occurs during decryption
     */
    protected String decryptResponseData(AesCipherPayload responsePayload, SecretKey sessionKey) throws Exception {
        return AesGcmCryptoService.decryptFromBase64(
                responsePayload.encryptedDataBase64(),
                sessionKey,
                responsePayload.ivBase64()
        );
    }
}
