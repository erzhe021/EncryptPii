package com.ikea.crypto.client.api;

import com.fasterxml.jackson.core.JsonProcessingException;
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
import java.net.http.HttpResponse;
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
            responsePayload = cryptoHttpClient.postBidirectional(
                    bidirectionalPath, requestPayload, encrypted.context().sessionKeyTransport());
        } catch (CryptoHttpClient.HttpStatusException failure) {
            serverKeyInfo = cryptoHttpClient.getRefreshedKeyFromFailure(failure);
            if (serverKeyInfo == null) {
                throw failure;
            }
            encrypted = cryptoClient.encrypt(plaintext, serverKeyInfo.keyId(), serverKeyInfo.publicKey());
            requestPayload = encrypted.payload();
            responsePayload = cryptoHttpClient.postBidirectional(
                    bidirectionalPath, requestPayload, encrypted.context().sessionKeyTransport());
        }

        long httpTime = System.currentTimeMillis();

        String decryptedServerResponse = cryptoClient.decrypt(responsePayload, encrypted.context());

        Result<DemoSensitiveResponse> demoSensitiveResponse = objectMapper.readValue(
                decryptedServerResponse,
                new TypeReference<>() {
                });

        long finish = System.currentTimeMillis();

        return Map.of(
                "request", Map.of("plain", demoSensitiveRequest, "cipher", requestPayload,
                        "headers", sessionHeaders(encrypted.context().sessionKeyTransport())),
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
            demoPlainResponse = cryptoHttpClient.postRequestOnly(
                    requestOnlyPath, requestPayload, encrypted.context().sessionKeyTransport());
        } catch (CryptoHttpClient.HttpStatusException failure) {
            serverKeyInfo = cryptoHttpClient.getRefreshedKeyFromFailure(failure);
            if (serverKeyInfo == null) {
                throw failure;
            }
            encrypted = cryptoClient.encrypt(plaintext, serverKeyInfo.keyId(), serverKeyInfo.publicKey());
            requestPayload = encrypted.payload();
            demoPlainResponse = cryptoHttpClient.postRequestOnly(
                    requestOnlyPath, requestPayload, encrypted.context().sessionKeyTransport());
        }

        long httpTime = System.currentTimeMillis();

        return Map.of(
                "request", Map.of("plain", demoSensitiveRequest, "cipher", requestPayload,
                        "headers", sessionHeaders(encrypted.context().sessionKeyTransport())),
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
        return responseOnly(demoPlainRequest, responseOnlyPath);
    }

    @PostMapping("/response-only/client-exception")
    public Map<String, Object> responseOnlyClientException(
            @RequestBody(required = false) DemoPlainRequest request) throws Exception {
        return responseOnly(request, responseOnlyPath + "/client-exception");
    }

    @PostMapping("/response-only/system-exception")
    public Map<String, Object> responseOnlySystemException(
            @RequestBody(required = false) DemoPlainRequest request) throws Exception {
        return responseOnly(request, responseOnlyPath + "/system-exception");
    }

    @PostMapping("/response-only/business-exception")
    public Map<String, Object> responseOnlyBusinessException(
            @RequestBody(required = false) DemoPlainRequest request) throws Exception {
        return responseOnly(request, responseOnlyPath + "/business-exception");
    }

    private Map<String, Object> responseOnly(DemoPlainRequest demoPlainRequest, String path) throws Exception {
        long startTime = System.currentTimeMillis();
        String data = demoPlainRequest == null ? null : demoPlainRequest.data();
        log.debug("starting response-only RSA encryption with request data: {}", data);

        // Generate a new session key for AES encryption
        SecretKey sessionKey = generateSessionKey();
        CryptoHttpClient.ServerKeyInfo serverKeyInfo = cryptoHttpClient.fetchServerKeyInfo();
        SessionKeyTransport sessionTransport =
                SessionKeyTransport.fromGeneratedKey(serverKeyInfo.keyId(), sessionKey, serverKeyInfo.publicKey());

        long requestPrepared = System.currentTimeMillis();

        HttpResponse<String> httpResponse =
                cryptoHttpClient.postResponseOnlyDetailed(path, demoPlainRequest, sessionTransport);
        serverKeyInfo = cryptoHttpClient.getRefreshedKeyFromResponse(path, httpResponse);
        if (serverKeyInfo != null) {
            sessionKey = generateSessionKey();
            sessionTransport =
                    SessionKeyTransport.fromGeneratedKey(serverKeyInfo.keyId(), sessionKey, serverKeyInfo.publicKey());
            httpResponse =
                    cryptoHttpClient.postResponseOnlyDetailed(path, demoPlainRequest, sessionTransport);
        }
        long httpTime = System.currentTimeMillis();

        var rawResponse = objectMapper.readTree(httpResponse.body());
        boolean encryptedResponse = httpResponse.statusCode() == 200
                || (rawResponse != null
                && (rawResponse.has("ivBase64") || rawResponse.has("encryptedDataBase64")));
        Object cipherResponse = "N/A";
        var plainResponse = rawResponse;
        if (encryptedResponse) {
            CipherResponsePayload responsePayload =
                    objectMapper.treeToValue(rawResponse, CipherResponsePayload.class);
            plainResponse = objectMapper.readTree(cryptoClient.decrypt(responsePayload, sessionKey));
            cipherResponse = responsePayload;
        }
        long finish = System.currentTimeMillis();

        return Map.of(
                "request", Map.of(
                        "plain", demoPlainRequest == null ? "no data" : demoPlainRequest,
                        "headers", sessionHeaders(sessionTransport)),
                "response", Map.of("plain", plainResponse == null ? "N/A" : plainResponse,
                        "cipher", cipherResponse, "status", httpResponse.statusCode()),
                "latency in ms", new LatencyInMs(
                        (finish - startTime),
                        (requestPrepared - startTime),
                        (httpTime - requestPrepared),
                        (finish - httpTime)
                )
        );
    }

    private String toJsonString(DemoSensitiveRequest data) throws JsonProcessingException {
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

    private Map<String, String> sessionHeaders(SessionKeyTransport sessionTransport) {
        return Map.of(
                CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_KEY_ID, sessionTransport.keyId(),
                CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_SESSION_KEY,
                sessionTransport.encryptedSessionKeyBase64());
    }

}
