package com.example.demo.client;

import com.example.demo.crypto.PlainData;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhCryptoClient;
import com.example.demo.crypto.ecdh.EcdhHttpCryptoClient;
import com.example.demo.crypto.ecdh.EcdhResponseOnlyRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.http.HttpResponse;
import java.util.Map;

@RestController
@RequestMapping("/crypto/client/ecdh")
public class CryptoClientEcdhController extends AbstractCryptoClientController {

    private final EcdhCryptoClient ecdhCryptoClient;
    private final String ecdhBidirectionalPath;
    private final String ecdhRequestOnlyPath;
    private final String ecdhResponseOnlyPath;

    public CryptoClientEcdhController(
            @Value("${crypto.server.base-url:http://localhost:9090}") String serverBaseUrl,
            @Value("${crypto.server.endpoints.ecdh.public-key:/crypto/server/ecdh/public-key}") String ecdhPublicKeyPath,
            @Value("${crypto.server.endpoints.ecdh.bidirectional:/crypto/server/ecdh/bidirectional}") String ecdhBidirectionalPath,
            @Value("${crypto.server.endpoints.ecdh.request-only:/crypto/server/ecdh/request-only}") String ecdhRequestOnlyPath,
            @Value("${crypto.server.endpoints.ecdh.response-only:/crypto/server/ecdh/response-only}") String ecdhResponseOnlyPath
    ) {
        super(serverBaseUrl);
        this.ecdhBidirectionalPath = ecdhBidirectionalPath;
        this.ecdhRequestOnlyPath = ecdhRequestOnlyPath;
        this.ecdhResponseOnlyPath = ecdhResponseOnlyPath;
        this.ecdhCryptoClient = new EcdhCryptoClient(new EcdhHttpCryptoClient(serverBaseUri, ecdhPublicKeyPath));
    }

    @PostMapping("/bidirectional")
    public Map<String, Object> bidirectionalEcdhEncrypt(@RequestBody PlainData plainData) throws Exception {
        EcdhCryptoClient.EncryptionResult encrypted = ecdhCryptoClient.encrypt(toJsonString(plainData));
        EcdhCipherPayload requestPayload = encrypted.payload();
        HttpResponse<String> response = sendJsonRequest(ecdhBidirectionalPath, requestPayload);
        ensureSuccess(response, "bidirectional ECDH encrypt");
        EcdhCipherPayload responsePayload = objectMapper.readValue(response.body(), EcdhCipherPayload.class);
        String decryptedServerResponse = ecdhCryptoClient.decrypt(responsePayload, encrypted.context());
        PlainData decryptedServerResponseData = objectMapper.readValue(decryptedServerResponse, PlainData.class);

        return Map.of(
                "request", Map.of("data", plainData.data(), "encrypted", requestPayload),
                "response", Map.of("data", decryptedServerResponseData.data(), "encrypted", responsePayload)
        );
    }

    @PostMapping("/request-only")
    public Map<String, Object> requestOnlyEcdhEncrypt(@RequestBody PlainData plainData) throws Exception {
        EcdhCryptoClient.EncryptionResult encrypted = ecdhCryptoClient.encrypt(toJsonString(plainData));
        EcdhCipherPayload requestPayload = encrypted.payload();


        HttpResponse<String> response = sendJsonRequest(ecdhRequestOnlyPath, requestPayload);
        ensureSuccess(response, "request-only ECDH encrypt");
        PlainData responsePlainData = objectMapper.readValue(response.body(), PlainData.class);

        return Map.of(
                "request", Map.of("data", plainData.data(), "encrypted", requestPayload),
                "response", Map.of("data", responsePlainData.data())
        );
    }

    @PostMapping("/response-only")
    public Map<String, Object> responseOnlyEcdhEncrypt(@RequestBody(required = false) PlainData plainData) throws Exception {
        EcdhCryptoClient.ResponseOnlySession responseOnlySession = ecdhCryptoClient.createResponseOnlySession(
                plainData == null ? null : plainData.data()
        );
        EcdhResponseOnlyRequest requestPayload = responseOnlySession.request();
        HttpResponse<String> response = sendJsonRequest(ecdhResponseOnlyPath, requestPayload);
        ensureSuccess(response, "response-only ECDH encrypt");
        EcdhCipherPayload responsePayload = objectMapper.readValue(response.body(), EcdhCipherPayload.class);
        // Decrypt the response using the session context
        String decryptedResponseData = ecdhCryptoClient.decrypt(responsePayload, responseOnlySession.context());
        PlainData decryptedServerResponseData = objectMapper.readValue(decryptedResponseData, PlainData.class);

        return Map.of(
                "request", requestPayload,
                "response", Map.of("data", decryptedServerResponseData.data(), "encrypted", responsePayload)
        );
    }

}
