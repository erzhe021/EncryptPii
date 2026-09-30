package com.ikea.crypto.client.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.client.core.CryptoClient;
import com.ikea.crypto.client.core.CryptoHttpClient;
import com.ikea.crypto.client.model.*;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.CipherResponsePayload;
import com.ikea.crypto.stc.model.SessionKeyTransport;
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
            @Value("${crypto.server.base-url:http:/localhost:9090}") String serverBaseUrl,
            @Value("${crypto.server.endpoints.public-key:/crypto/server/public-key}") String publicKeyPath,
            @Value("${crypto.server.endpoints.bidirectional:/crypto/server/bidirectional}") String bidirectionalPath,
            @Value("${crypto.server.endpoints.request-only:/crypto/server/request-only}") String requestOnlyPath,
            @Value("${crypto.server.endpoints.response-only:/crypto/server/response-only}") String responseOnlyPath
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

        CryptoHttpClient.ServerKeyInfo serverKeyInfo = cryptoHttpClient.fetchServerKeyInfo();
        CryptoClient.EncryptionResult encrypted = cryptoClient.encrypt(
                toJsonString(demoSensitiveRequest), serverKeyInfo.keyId(), serverKeyInfo.publicKey());
        CipherRequestPayload requestPayload = encrypted.payload();

        long encryptedTime = System.currentTimeMillis();
        log.debug("request encryption time: {} ms", encryptedTime - startTime);

        CipherResponsePayload responsePayload = cryptoHttpClient.postBidirectional(bidirectionalPath, requestPayload);

        long httpTime = System.currentTimeMillis();
        log.debug("http request-response time: {} ms", httpTime - encryptedTime);

        String decryptedServerResponse = cryptoClient.decrypt(responsePayload, encrypted.context());
        DemoSensitiveResponse demoSensitiveResponse =
                objectMapper.readValue(decryptedServerResponse, DemoSensitiveResponse.class);

        long finish = System.currentTimeMillis();
        log.debug("response decryption time: {} ms", finish - httpTime);

        return Map.of(
                "request", Map.of("plain", demoSensitiveRequest, "cipher", requestPayload),
                "response", Map.of("plain", demoSensitiveResponse, "cipher", responsePayload),
                "latency", new LatencyInMs(
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
        CryptoHttpClient.ServerKeyInfo serverKeyInfo = cryptoHttpClient.fetchServerKeyInfo();
        CryptoClient.EncryptionResult encrypted = cryptoClient.encrypt(
                toJsonString(demoSensitiveRequest), serverKeyInfo.keyId(), serverKeyInfo.publicKey());
        CipherRequestPayload requestPayload = encrypted.payload();

        long encryptedTime = System.currentTimeMillis();
        log.debug("request encryption time: {} ms", encryptedTime - startTime);

        DemoPlainResponse demoPlainResponse = cryptoHttpClient.postRequestOnly(requestOnlyPath, requestPayload);

        long httpTime = System.currentTimeMillis();
        log.debug("http request-response time: {} ms", httpTime - encryptedTime);

        return Map.of(
                "request", Map.of("plain", demoSensitiveRequest, "cipher", requestPayload),
                "response", demoPlainResponse,
                "latency", new LatencyInMs(
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
        log.debug("request preparation time: {} ms", requestPrepared - startTime);

        CipherResponsePayload responsePayload =
                cryptoHttpClient.postResponseOnly(responseOnlyPath, demoPlainRequest, sessionTransport);
        long httpTime = System.currentTimeMillis();
        log.debug("http request-response time: {} ms", httpTime - requestPrepared);

        // Decrypt the response data using the session key and IV
        String decryptedResponseData = cryptoClient.decrypt(responsePayload, sessionKey);
        DemoSensitiveResponse demoSensitiveResponse =
                objectMapper.readValue(decryptedResponseData, DemoSensitiveResponse.class);
        log.debug("response plain data after decryption: {}", demoSensitiveResponse);

        return Map.of(
                "request", demoPlainRequest == null ? "no data" : demoPlainRequest,
                "response", Map.of("plain", demoSensitiveResponse, "cipher", responsePayload),
                "latency", new LatencyInMs(
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
