package com.example.demo.client;

import com.example.demo.crypto.AesCipherPayload;
import com.example.demo.crypto.SessionKeyTransport;
import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.DefaultAesCipherPayload;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.PlainData;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;

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

    protected String resolveData(PlainData plainData) {
        return plainData == null || plainData.data() == null ? "Hello, World!" : plainData.data();
    }

    protected String toPlainDataJson(String data) throws Exception {
        return objectMapper.writeValueAsString(Map.of("data", data));
    }

    protected HttpResponse<String> sendJsonRequest(String path, Object requestBody) throws Exception {
        return httpClient.send(buildJsonRequest(serverBaseUri.resolve(path), requestBody), HttpResponse.BodyHandlers.ofString());
    }

    protected HttpRequest buildJsonRequest(URI endpoint, Object requestBody) throws Exception {
        return HttpRequest.newBuilder(endpoint)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestBody)))
                .build();
    }

    protected Map<String, Object> postForMap(String path, Object requestBody, String operation) throws Exception {
        return postForMap(buildJsonRequest(serverBaseUri.resolve(path), requestBody), operation);
    }

    protected Map<String, Object> postForMap(HttpRequest request, String operation) throws Exception {
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        ensureSuccess(response, operation);
        return objectMapper.readValue(response.body(), Map.class);
    }

    protected HttpRequest buildSessionKeyRequest(URI endpoint, String data, SessionKeyTransport sessionKeyTransport) throws Exception {
        return sessionKeyTransport.apply(HttpRequest.newBuilder(endpoint)
                        .header("Content-Type", "application/json"))
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(Map.of("data", data))))
                .build();
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

    protected String decryptResponseData(Map<String, Object> responsePayload, SecretKey sessionKey) throws Exception {
        return decryptResponseData(objectMapper.convertValue(responsePayload, DefaultAesCipherPayload.class), sessionKey);
    }

    protected String decryptResponseData(AesCipherPayload responsePayload, SecretKey sessionKey) throws Exception {
        String encryptedDataBase64 = responsePayload.encryptedDataBase64();
        String ivBase64 = responsePayload.ivBase64();

        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(
                Cipher.DECRYPT_MODE,
                sessionKey,
                new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, EncodingUtils.fromBase64(ivBase64))
        );
        return new String(
                aesCipher.doFinal(EncodingUtils.fromBase64(encryptedDataBase64)),
                StandardCharsets.UTF_8
        );
    }
}
