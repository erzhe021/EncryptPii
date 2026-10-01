package com.ikea.crypto.client.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.client.core.CryptoClient;
import com.ikea.crypto.client.core.CryptoHttpClient;
import com.ikea.crypto.client.model.*;
import com.ikea.crypto.stc.model.CipherDataPayload;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.EphemeralKeyResponse;
import com.ikea.crypto.stc.model.VerificationKeyResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/crypto/client/ecdh")
@Slf4j
public class CryptoClientController {

    private final CryptoHttpClient cryptoHttpClient;
    private final CryptoClient cryptoClient;
    private final ObjectMapper objectMapper;
    private final String ecdhBidirectionalPath;
    private final String ecdhRequestOnlyPath;
    private final String ecdhResponseOnlyPath;

    public CryptoClientController(
            CryptoHttpClient cryptoHttpClient,
            CryptoClient cryptoClient,
            ObjectMapper objectMapper,
            @Value("${crypto.server.endpoints.ecdh.bidirectional:/crypto/server/ecdh/bidirectional}") String ecdhBidirectionalPath,
            @Value("${crypto.server.endpoints.ecdh.request-only:/crypto/server/ecdh/request-only}") String ecdhRequestOnlyPath,
            @Value("${crypto.server.endpoints.ecdh.response-only:/crypto/server/ecdh/response-only}") String ecdhResponseOnlyPath
    ) {
        this.cryptoHttpClient = cryptoHttpClient;
        this.cryptoClient = cryptoClient;
        this.objectMapper = objectMapper;
        this.ecdhBidirectionalPath = ecdhBidirectionalPath;
        this.ecdhRequestOnlyPath = ecdhRequestOnlyPath;
        this.ecdhResponseOnlyPath = ecdhResponseOnlyPath;
    }

    @PostMapping("/bidirectional")
    public Map<String, Object> bidirectionalEcdhEncrypt(@RequestBody DemoSensitiveRequest request) throws Exception {
        long startTime = System.currentTimeMillis();

        EphemeralKeyResponse ephemeralResponse = cryptoHttpClient.fetchEphemeralPublicKey();
        VerificationKeyResponse ecdsaResponse = cryptoHttpClient.fetchEcdsaPublicKey();
        CryptoClient.EncryptionResult encrypted = cryptoClient.encrypt(toJsonString(request), ephemeralResponse, ecdsaResponse);
        CipherRequestPayload requestPayload = encrypted.payload();
        long encryptedTime = System.currentTimeMillis();

        CipherDataPayload responsePayload = cryptoHttpClient.post(ecdhBidirectionalPath, requestPayload, CipherDataPayload.class);
        long responseTime = System.currentTimeMillis();

        String decryptedServerResponse = cryptoClient.decrypt(responsePayload, encrypted.context());
        DemoSensitiveResponse demoSensitiveResponse = objectMapper.readValue(decryptedServerResponse, DemoSensitiveResponse.class);
        long decryptedTime = System.currentTimeMillis();

        return Map.of(
                "request", Map.of("plain", request, "cipher", requestPayload),
                "response", Map.of("plain", demoSensitiveResponse, "cipher", responsePayload),
                "latency", new LatencyInMs(
                        decryptedTime - startTime,
                        encryptedTime - startTime,
                        responseTime - encryptedTime,
                        decryptedTime - responseTime
                )
        );
    }

    @PostMapping("/request-only")
    public Map<String, Object> requestOnlyEcdhEncrypt(@RequestBody DemoSensitiveRequest request) throws Exception {
        long startTime = System.currentTimeMillis();
        EphemeralKeyResponse ephemeralResponse = cryptoHttpClient.fetchEphemeralPublicKey();
        VerificationKeyResponse ecdsaResponse = cryptoHttpClient.fetchEcdsaPublicKey();
        CryptoClient.EncryptionResult encrypted = cryptoClient.encrypt(toJsonString(request), ephemeralResponse, ecdsaResponse);
        CipherRequestPayload requestPayload = encrypted.payload();
        long encryptedTime = System.currentTimeMillis();
        DemoPlainResponse demoPlainResponse = cryptoHttpClient.post(ecdhRequestOnlyPath, requestPayload, DemoPlainResponse.class);
        long responseTime = System.currentTimeMillis();

        return Map.of(
                "request", Map.of("plain", request, "cipher", requestPayload),
                "response", demoPlainResponse,
                "latency", new LatencyInMs(
                        responseTime - startTime,
                        encryptedTime - startTime,
                        responseTime - encryptedTime,
                        0
                )
        );
    }

    @PostMapping("/response-only")
    public Map<String, Object> responseOnlyEcdhEncrypt(@RequestBody(required = false) DemoPlainRequest request) throws Exception {
        long startTime = System.currentTimeMillis();

        EphemeralKeyResponse ephemeralResponse = cryptoHttpClient.fetchEphemeralPublicKey();
        VerificationKeyResponse ecdsaResponse = cryptoHttpClient.fetchEcdsaPublicKey();
        CryptoClient.ResponseOnlySession responseOnlySession = cryptoClient.createResponseOnlySession(
                request,
                ephemeralResponse,
                ecdsaResponse
        );
        PlainRequestPayload requestPayload = responseOnlySession.request();
        long encryptedTime = System.currentTimeMillis();

        CipherDataPayload responsePayload = cryptoHttpClient.post(ecdhResponseOnlyPath, requestPayload, CipherDataPayload.class);
        long responseTime = System.currentTimeMillis();

        String decryptedResponseData = cryptoClient.decrypt(responsePayload, responseOnlySession.context());
        DemoSensitiveResponse demoSensitiveResponse = objectMapper.readValue(decryptedResponseData, DemoSensitiveResponse.class);
        long decryptedTime = System.currentTimeMillis();

        return Map.of(
                "request", requestPayload,
                "response", Map.of("plain", demoSensitiveResponse, "cipher", responsePayload),
                "latency", new LatencyInMs(
                        decryptedTime - startTime,
                        encryptedTime - startTime,
                        responseTime - encryptedTime,
                        decryptedTime - responseTime
                )
        );
    }

    private String toJsonString(DemoSensitiveRequest request) throws Exception {
        if (request == null) {
            throw new IllegalArgumentException("DemoSensitiveRequest cannot be null");
        }
        return objectMapper.writeValueAsString(request);
    }
}
