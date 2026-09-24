package com.example.demo.client;

import com.example.demo.crypto.*;
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

    protected void validatePlainData(PlainData data) {
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

    protected HttpRequest buildJsonRequest(URI endpoint, Object requestBody) throws Exception {
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

    protected Map<String, Object> postForMap(String path, Object requestBody, String operation) throws Exception {
        return postForMap(buildJsonRequest(serverBaseUri.resolve(path), requestBody), operation);
    }

    protected Map<String, Object> postForMap(HttpRequest request, String operation) throws Exception {
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        ensureSuccess(response, operation);
        return objectMapper.readValue(response.body(), Map.class);
    }

    protected HttpRequest buildSessionKeyRequest(URI endpoint, String data, SessionKeyTransport sessionKeyTransport) throws Exception {
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
