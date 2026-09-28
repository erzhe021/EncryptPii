package com.ikea.crypto.client.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.client.core.CryptoClient;
import com.ikea.crypto.client.core.CryptoHttpClient;
import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.model.demo.PlainData;
import com.ikea.crypto.common.model.payload.CipherRequestPayload;
import com.ikea.crypto.common.model.payload.CipherResponsePayload;
import com.ikea.crypto.common.model.payload.SessionKeyTransport;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.URI;
import java.security.PublicKey;
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
            @Value("${crypto.server.endpoints.rsa.public-key:/crypto/server/public-key}") String publicKeyPath,
            @Value("${crypto.server.endpoints.rsa.bidirectional:/crypto/server/bidirectional}") String bidirectionalPath,
            @Value("${crypto.server.endpoints.rsa.request-only:/crypto/server/request-only}") String requestOnlyPath,
            @Value("${crypto.server.endpoints.rsa.response-only:/crypto/server/response-only}") String responseOnlyPath
    ) {
        this.objectMapper = new ObjectMapper();
        this.bidirectionalPath = bidirectionalPath;
        this.requestOnlyPath = requestOnlyPath;
        this.responseOnlyPath = responseOnlyPath;
        this.cryptoClient = new CryptoClient();
        this.cryptoHttpClient = new CryptoHttpClient(URI.create(serverBaseUrl), publicKeyPath);
    }

    @PostMapping("/bidirectional")
    public Map<String, Object> bidirectionalEncrypt(@RequestBody PlainData plainData) throws Exception {
        log.debug("starting bidirectional RSA encryption with request data: {}", plainData.data());
        PublicKey serverPublicKey = cryptoHttpClient.fetchServerPublicKey();
        CryptoClient.EncryptionResult encrypted = cryptoClient.encrypt(toJsonString(plainData), serverPublicKey);
        CipherRequestPayload requestPayload = encrypted.payload();

        CipherResponsePayload responsePayload = cryptoHttpClient.postBidirectional(bidirectionalPath, requestPayload);
        String decryptedServerResponse = cryptoClient.decrypt(responsePayload, encrypted.context());
        PlainData responsePlainData = objectMapper.readValue(decryptedServerResponse, PlainData.class);
        log.debug("response plain data after decryption: {}", responsePlainData.data());

        return Map.of(
                "request", Map.of("data", plainData.data(), "encrypted", requestPayload),
                "response", Map.of("data", responsePlainData.data(), "encrypted", responsePayload)
        );
    }

    @PostMapping("/request-only")
    public Map<String, Object> requestOnlyEncrypt(@RequestBody PlainData plainData) throws Exception {
        log.debug("starting request-only RSA encryption with request data: {}", plainData.data());
        PublicKey serverPublicKey = cryptoHttpClient.fetchServerPublicKey();
        CryptoClient.EncryptionResult encrypted = cryptoClient.encrypt(toJsonString(plainData), serverPublicKey);
        CipherRequestPayload requestPayload = encrypted.payload();

        PlainData responseData = cryptoHttpClient.postRequestOnly(requestOnlyPath, requestPayload);
        log.debug("response plain data: {}", responseData.data());

        return Map.of(
                "request", Map.of("data", plainData.data(), "encrypted", requestPayload),
                "response", Map.of("data", responseData.data())
        );
    }

    @PostMapping("/response-only")
    public Map<String, Object> responseOnlyEncrypt(@RequestBody(required = false) PlainData plainData) throws Exception {
        String data = plainData == null ? null : plainData.data();
        log.debug("starting response-only RSA encryption with request data: {}", data);

        // Generate a new session key for AES encryption
        SecretKey sessionKey = generateSessionKey();
        PublicKey publicKey = cryptoHttpClient.fetchServerPublicKey();
        SessionKeyTransport sessionTransport = SessionKeyTransport.fromGeneratedKey(sessionKey, publicKey);

        CipherResponsePayload responsePayload = cryptoHttpClient.postResponseOnly(responseOnlyPath, data, sessionTransport);

        // Decrypt the response data using the session key and IV
        String decryptedResponseData = cryptoClient.decrypt(responsePayload, sessionKey);
        PlainData responsePlainData = objectMapper.readValue(decryptedResponseData, PlainData.class);
        log.debug("response plain data after decryption: {}", responsePlainData.data());

        return Map.of(
                "request", Map.of("data", data == null ? "null" : data),
                "response", Map.of("data", responsePlainData.data(), "encrypted", responsePayload)
        );
    }

    private void validatePlainData(PlainData data) {
        if (data == null || data.data() == null || data.data().isEmpty()) {
            throw new IllegalArgumentException("PlainData cannot be null or empty");
        }
    }

    private String toJsonString(PlainData data) throws Exception {
        validatePlainData(data);
        return objectMapper.writeValueAsString(data);
    }

    private SecretKey generateSessionKey() throws Exception {
        log.debug("start to generate session key");
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        return keyGenerator.generateKey();
    }
}
