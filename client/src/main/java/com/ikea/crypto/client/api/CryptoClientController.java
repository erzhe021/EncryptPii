package com.ikea.crypto.client.api;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.client.constant.CryptoConstants;
import com.ikea.crypto.client.core.CryptoClient;
import com.ikea.crypto.client.core.CryptoHttpClient;
import com.ikea.crypto.client.model.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.URI;
import java.util.Map;

@RestController
@RequestMapping("/crypto/client")
@Slf4j
public class CryptoClientController {

    private final ObjectMapper objectMapper;
    private final CryptoClient cryptoClient;
    private final CryptoHttpClient cryptoHttpClient;
    private final String bidirectionalPath;
    private final String requestOnlyPath;
    private final String responseOnlyPath;

    public CryptoClientController(
            @Value("${crypto.server.base-url}") String serverBaseUrl,
            @Value("${crypto.server.endpoints.public-key}") String publicKeyPath,
            @Value("${crypto.server.endpoints.bidirectional}") String bidirectionalPath,
            @Value("${crypto.server.endpoints.request-only}") String requestOnlyPath,
            @Value("${crypto.server.endpoints.response-only}") String responseOnlyPath
    ) {
        this.objectMapper = new ObjectMapper();
        this.bidirectionalPath = bidirectionalPath;
        this.requestOnlyPath = requestOnlyPath;
        this.responseOnlyPath = responseOnlyPath;
        this.cryptoClient = new CryptoClient();
        this.cryptoHttpClient = new CryptoHttpClient(URI.create(serverBaseUrl), publicKeyPath);
    }

    @PostMapping("/bidirectional")
    public Map<String, Object> bidirectionalEncrypt(@RequestBody DemoSensitiveRequest demoSensitiveRequest)
            throws Exception {

        long startTime = System.currentTimeMillis();
        log.debug("starting bidirectional RSA encryption");

        String plaintext = toJsonString(demoSensitiveRequest);
        CryptoHttpClient.ServerKeyInfo serverKeyInfo = cryptoHttpClient.fetchServerKeyInfo();
        CryptoClient.EncryptionResult encrypted = cryptoClient.encrypt(
                plaintext, serverKeyInfo.keyId(), serverKeyInfo.publicKey());
        CipherRequestPayload requestPayload = encrypted.payload();

        long encryptedTime = System.currentTimeMillis();

        CipherResponsePayload responsePayload;
        try {
            responsePayload = cryptoHttpClient.postBidirectional(bidirectionalPath, requestPayload);
        } catch (CryptoHttpClient.HttpStatusException failure) {
            serverKeyInfo = cryptoHttpClient.getRefreshedKeyFromFailure(failure);
            if (serverKeyInfo == null) {
                throw failure;
            }
            encrypted = cryptoClient.encrypt(plaintext, serverKeyInfo.keyId(), serverKeyInfo.publicKey());
            requestPayload = encrypted.payload();
            responsePayload = cryptoHttpClient.postBidirectional(bidirectionalPath, requestPayload);
        }

        long httpTime = System.currentTimeMillis();

        String decryptedServerResponse = cryptoClient.decrypt(responsePayload, encrypted.context());

        Result<DemoSensitiveResponse> demoSensitiveResponse = objectMapper.readValue(
                decryptedServerResponse,
                new TypeReference<>() {
                });

        long finish = System.currentTimeMillis();

        return Map.of(
                "request", Map.of("plain", demoSensitiveRequest, "cipher", requestPayload),
                "response", Map.of("plain", demoSensitiveResponse, "cipher", responsePayload),
                "latency in ms", new LatencyInMs(
                        (finish - startTime),
                        (encryptedTime - startTime),
                        (httpTime - encryptedTime),
                        (finish - httpTime)
                )
        );
    }

    @PostMapping("/request-only")
    public Map<String, Object> requestOnlyEncrypt(@RequestBody DemoSensitiveRequest demoSensitiveRequest)
            throws Exception {
        long startTime = System.currentTimeMillis();
        log.debug("starting request-only RSA encryption");
        String plaintext = toJsonString(demoSensitiveRequest);
        CryptoHttpClient.ServerKeyInfo serverKeyInfo = cryptoHttpClient.fetchServerKeyInfo();
        CryptoClient.EncryptionResult encrypted = cryptoClient.encrypt(
                plaintext, serverKeyInfo.keyId(), serverKeyInfo.publicKey());
        CipherRequestPayload requestPayload = encrypted.payload();

        long encryptedTime = System.currentTimeMillis();

        Result<DemoPlainResponse> demoPlainResponse;
        try {
            demoPlainResponse = cryptoHttpClient.postRequestOnly(requestOnlyPath, requestPayload);
        } catch (CryptoHttpClient.HttpStatusException failure) {
            serverKeyInfo = cryptoHttpClient.getRefreshedKeyFromFailure(failure);
            if (serverKeyInfo == null) {
                throw failure;
            }
            encrypted = cryptoClient.encrypt(plaintext, serverKeyInfo.keyId(), serverKeyInfo.publicKey());
            requestPayload = encrypted.payload();
            demoPlainResponse = cryptoHttpClient.postRequestOnly(requestOnlyPath, requestPayload);
        }

        long httpTime = System.currentTimeMillis();

        return Map.of(
                "request", Map.of("plain", demoSensitiveRequest, "cipher", requestPayload),
                "response", demoPlainResponse,
                "latency in ms", new LatencyInMs(
                        (System.currentTimeMillis() - startTime),
                        (encryptedTime - startTime),
                        (httpTime - encryptedTime),
                        (System.currentTimeMillis() - httpTime)
                )
        );
    }

    @PostMapping("/response-only")
    public Map<String, Object> responseOnlyEncrypt(@RequestBody(required = false) DemoPlainRequest demoPlainRequest)
            throws Exception {
        long startTime = System.currentTimeMillis();
        String data = demoPlainRequest == null ? null : demoPlainRequest.data();
        log.debug("starting response-only RSA encryption with request data: {}", data);

        // Generate a new session key for AES encryption
        SecretKey sessionKey = generateSessionKey();
        CryptoHttpClient.ServerKeyInfo serverKeyInfo = cryptoHttpClient.fetchServerKeyInfo();
        SessionKeyTransport sessionTransport =
                SessionKeyTransport.fromGeneratedKey(serverKeyInfo.keyId(), sessionKey, serverKeyInfo.publicKey());

        long requestPrepared = System.currentTimeMillis();

        CipherResponsePayload responsePayload;
        try {
            responsePayload =
                    cryptoHttpClient.postResponseOnly(responseOnlyPath, demoPlainRequest, sessionTransport);
        } catch (CryptoHttpClient.HttpStatusException failure) {
            serverKeyInfo = cryptoHttpClient.getRefreshedKeyFromFailure(failure);
            if (serverKeyInfo == null) {
                throw failure;
            }
            sessionKey = generateSessionKey();
            sessionTransport =
                    SessionKeyTransport.fromGeneratedKey(serverKeyInfo.keyId(), sessionKey, serverKeyInfo.publicKey());
            responsePayload =
                    cryptoHttpClient.postResponseOnly(responseOnlyPath, demoPlainRequest, sessionTransport);
        }
        long httpTime = System.currentTimeMillis();

        // Decrypt the response data using the session key and IV
        String decryptedResponseData = cryptoClient.decrypt(responsePayload, sessionKey);
        Result<DemoSensitiveResponse> demoSensitiveResponse = objectMapper.readValue(
                decryptedResponseData,
                new TypeReference<>() {
                });

        return Map.of(
                "request", demoPlainRequest == null ? "no data" : demoPlainRequest,
                "response", Map.of("plain", demoSensitiveResponse, "cipher", responsePayload),
                "latency in ms", new LatencyInMs(
                        (System.currentTimeMillis() - startTime),
                        (requestPrepared - startTime),
                        (httpTime - requestPrepared),
                        (System.currentTimeMillis() - httpTime)
                )
        );
    }

    private String toJsonString(DemoSensitiveRequest data) throws Exception {
        if (data == null) {
            throw new IllegalArgumentException("UserRequest cannot be null or empty");
        }
        return objectMapper.writeValueAsString(data);
    }

    private SecretKey generateSessionKey() throws Exception {
        log.debug("start to generate session key");
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        return keyGenerator.generateKey();
    }

}
