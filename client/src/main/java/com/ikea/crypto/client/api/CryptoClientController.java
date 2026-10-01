package com.ikea.crypto.client.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.client.core.CryptoClient;
import com.ikea.crypto.client.core.CryptoHttpClient;
import com.ikea.crypto.client.model.PlainData;
import com.ikea.crypto.stc.model.*;
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
    public Map<String, Object> bidirectionalEcdhEncrypt(@RequestBody PlainData plainData) throws Exception {
        EphemeralKeyResponse ephemeralResponse = cryptoHttpClient.fetchEphemeralPublicKey();
        VerificationKeyResponse ecdsaResponse = cryptoHttpClient.fetchEcdsaPublicKey();
        CryptoClient.EncryptionResult encrypted = cryptoClient.encrypt(toJsonString(plainData), ephemeralResponse, ecdsaResponse);
        CipherRequestPayload requestPayload = encrypted.payload();

        CipherDataPayload responsePayload = cryptoHttpClient.post(ecdhBidirectionalPath, requestPayload, CipherDataPayload.class);
        String decryptedServerResponse = cryptoClient.decrypt(responsePayload, encrypted.context());
        PlainData decryptedServerResponseData = objectMapper.readValue(decryptedServerResponse, PlainData.class);

        return Map.of(
                "request", Map.of("data", plainData.data(), "encrypted", requestPayload),
                "response", Map.of("data", decryptedServerResponseData.data(), "encrypted", responsePayload)
        );
    }

    @PostMapping("/request-only")
    public Map<String, Object> requestOnlyEcdhEncrypt(@RequestBody PlainData plainData) throws Exception {
        EphemeralKeyResponse ephemeralResponse = cryptoHttpClient.fetchEphemeralPublicKey();
        VerificationKeyResponse ecdsaResponse = cryptoHttpClient.fetchEcdsaPublicKey();
        CryptoClient.EncryptionResult encrypted = cryptoClient.encrypt(toJsonString(plainData), ephemeralResponse, ecdsaResponse);
        CipherRequestPayload requestPayload = encrypted.payload();

        PlainData responsePlainData = cryptoHttpClient.post(ecdhRequestOnlyPath, requestPayload, PlainData.class);

        return Map.of(
                "request", Map.of("data", plainData.data(), "encrypted", requestPayload),
                "response", Map.of("data", responsePlainData.data())
        );
    }

    @PostMapping("/response-only")
    public Map<String, Object> responseOnlyEcdhEncrypt(@RequestBody(required = false) PlainData plainData) throws Exception {
        EphemeralKeyResponse ephemeralResponse = cryptoHttpClient.fetchEphemeralPublicKey();
        VerificationKeyResponse ecdsaResponse = cryptoHttpClient.fetchEcdsaPublicKey();
        CryptoClient.ResponseOnlySession responseOnlySession = cryptoClient.createResponseOnlySession(
                plainData == null ? null : plainData.data(),
                ephemeralResponse,
                ecdsaResponse
        );
        PlainRequestPayload requestPayload = responseOnlySession.request();

        CipherDataPayload responsePayload = cryptoHttpClient.post(ecdhResponseOnlyPath, requestPayload, CipherDataPayload.class);
        String decryptedResponseData = cryptoClient.decrypt(responsePayload, responseOnlySession.context());
        PlainData decryptedServerResponseData = objectMapper.readValue(decryptedResponseData, PlainData.class);

        return Map.of(
                "request", requestPayload,
                "response", Map.of("data", decryptedServerResponseData.data(), "encrypted", responsePayload)
        );
    }

    private String toJsonString(PlainData data) throws Exception {
        if (data == null || data.data() == null || data.data().isEmpty()) {
            throw new IllegalArgumentException("PlainData cannot be null or empty");
        }
        return objectMapper.writeValueAsString(data);
    }
}
