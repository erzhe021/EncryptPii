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
public class CryptoEcdhClientController extends AbstractCryptoClientController {

    private final EcdhCryptoClient ecdhCryptoClient;

    public CryptoEcdhClientController(@Value("${crypto.server.base-url:http://localhost:9090}") String serverBaseUrl) {
        super(serverBaseUrl);
        this.ecdhCryptoClient = new EcdhCryptoClient(new EcdhHttpCryptoClient(serverBaseUri));
    }

    @PostMapping("/bidirectional")
    public Map<String, Object> bidirectionalEcdhEncrypt(@RequestBody(required = false) PlainData plainData) throws Exception {
        String data = resolveData(plainData);
        EcdhCipherPayload encrypted = ecdhCryptoClient.encrypt(toPlainDataJson(data));
        HttpResponse<String> response = sendJsonRequest("/crypto/server/ecdh/bidirectional", encrypted);
        ensureSuccess(response, "bidirectional ECDH encrypt");
        EcdhCipherPayload responsePayload = objectMapper.readValue(response.body(), EcdhCipherPayload.class);
        String decryptedServerResponse = ecdhCryptoClient.decrypt(responsePayload);
        PlainData decryptedServerResponseData = objectMapper.readValue(decryptedServerResponse, PlainData.class);

        return Map.of(
                "request", Map.of("data", data, "encrypted", encrypted),
                "response", Map.of("data", decryptedServerResponseData.data(), "encrypted", responsePayload)
        );
    }

    @PostMapping("/request-only")
    public Map<String, Object> requestOnlyEcdhEncrypt(@RequestBody(required = false) PlainData plainData) throws Exception {
        String data = resolveData(plainData);
        EcdhCipherPayload encrypted = ecdhCryptoClient.encrypt(toPlainDataJson(data));
        Map<String, Object> responseMap = postForMap("/crypto/server/ecdh/request-only", encrypted, "request-only ECDH encrypt");

        return Map.of(
                "request", Map.of("data", data, "encrypted", encrypted),
                "response", Map.of("data", responseMap.get("data"))
        );
    }

    @PostMapping("/response-only")
    public Map<String, Object> responseOnlyEcdhEncrypt(@RequestBody(required = false) PlainData plainData) throws Exception {
        String data = resolveData(plainData);
        EcdhResponseOnlyRequest requestPayload = ecdhCryptoClient.createResponseOnlyRequest(data);
        HttpResponse<String> response = sendJsonRequest("/crypto/server/ecdh/response-only", requestPayload);
        ensureSuccess(response, "response-only ECDH encrypt");
        EcdhCipherPayload responsePayload = objectMapper.readValue(response.body(), EcdhCipherPayload.class);
        String decryptedResponseData = ecdhCryptoClient.decrypt(responsePayload);
        PlainData decryptedServerResponseData = objectMapper.readValue(decryptedResponseData, PlainData.class);

        return Map.of(
                "request", requestPayload,
                "response", Map.of("data", decryptedServerResponseData.data(), "encrypted", responsePayload)
        );
    }
}
