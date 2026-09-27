package com.ikea.crypto.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.common.AesCipherPayload;
import com.ikea.crypto.common.CryptoConstants;
import com.ikea.crypto.common.PlainData;
import com.ikea.crypto.common.core.AesGcmCryptoService;
import com.ikea.crypto.common.rsa.SessionKeyTransport;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

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
@Slf4j
public abstract class AbstractClientController {

    protected final URI serverBaseUri;
    protected final HttpClient httpClient;
    protected final ObjectMapper objectMapper;

    protected AbstractClientController(String serverBaseUrl) {
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
        log.debug("【call api】start to call server endpoint to send json request");
        HttpResponse<String> response = httpClient.send(buildJsonRequest(serverBaseUri.resolve(path), requestBody), HttpResponse.BodyHandlers.ofString());
        ensureSuccess(response, path);
        return response;
    }

    protected HttpResponse<String> sendJsonRequestWithSessionKeyTransport(String data, String path, SessionKeyTransport sessionTransport) throws Exception {
        log.debug("【call api】start to call server endpoint to send json request with SessionKeyTransport");
        HttpResponse<String> response = httpClient.send(
                buildSessionKeyRequest(serverBaseUri.resolve(path), data, sessionTransport),
                HttpResponse.BodyHandlers.ofString()
        );
        ensureSuccess(response, path);
        return response;
    }

    private HttpRequest buildJsonRequest(URI endpoint, Object requestBody) throws Exception {
        if (requestBody == null) {
            return HttpRequest.newBuilder(endpoint)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
        } else {
            return HttpRequest.newBuilder(endpoint)
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestBody)))
                    .build();
        }
    }

    private HttpRequest buildSessionKeyRequest(URI endpoint, String data, SessionKeyTransport sessionKeyTransport) throws Exception {
        if (data != null) {
            return sessionKeyTransport.apply(
                            HttpRequest.newBuilder(endpoint).header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    )
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(new PlainData(data))))
                    .build();
        } else {
            return sessionKeyTransport.apply(
                            HttpRequest.newBuilder(endpoint).header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                    )
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build();
        }
    }

    private void ensureSuccess(HttpResponse<String> response, String path) {
        if (response.statusCode() != 200) {
            throw new IllegalStateException("request path: " + path + " failed: status=" + response.statusCode() + ", body=" + response.body());
        }
    }

    protected SecretKey generateSessionKey() throws Exception {
        log.debug("start to generate session key");
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        return keyGenerator.generateKey();
    }

    protected byte[] generateIv() {
        log.debug("start to generate IV");
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

}
