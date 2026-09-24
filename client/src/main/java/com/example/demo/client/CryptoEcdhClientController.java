package com.example.demo.client;

import com.example.demo.crypto.ClientSessionKeyTransport;
import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.PlainData;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhCryptoClient;
import com.example.demo.crypto.ecdh.EcdhHttpCryptoClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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

@RestController
@RequestMapping("/crypto/client/ecdh")
public class CryptoEcdhClientController {

    private final URI serverBaseUri;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final EcdhCryptoClient ecdhCryptoClient;

    public CryptoEcdhClientController(@Value("${crypto.server.base-url:http://localhost:9090}") String serverBaseUrl) {
        this.serverBaseUri = URI.create(serverBaseUrl);
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
        this.ecdhCryptoClient = new EcdhCryptoClient(new EcdhHttpCryptoClient(serverBaseUri));
    }

    @PostMapping("/bidirectional")
    public Map<String, Object> bidirectionalEcdhEncrypt(@RequestBody(required = false) PlainData plainData) throws Exception {
        String data = plainData == null || plainData.data() == null ? "Hello, World!" : plainData.data();
        String requestJson = objectMapper.writeValueAsString(Map.of("data", data));

        EcdhCipherPayload encrypted = ecdhCryptoClient.encrypt(requestJson);

        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve("/crypto/server/ecdh/bidirectional"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(encrypted)))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("bidirectional ECDH encrypt request failed: status=" + response.statusCode() + ", body=" + response.body());
        }

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
        String data = plainData == null || plainData.data() == null ? "Hello, World!" : plainData.data();
        String requestJson = objectMapper.writeValueAsString(Map.of("data", data));

        EcdhCryptoClient cryptoClient = new EcdhCryptoClient(new EcdhHttpCryptoClient(serverBaseUri));
        EcdhCipherPayload encrypted = cryptoClient.encrypt(requestJson);

        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve("/crypto/server/ecdh/request-only"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(encrypted)))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("request-only ECDH encrypt request failed: status=" + response.statusCode() + ", body=" + response.body());
        }

        Map<String, Object> responseMap = objectMapper.readValue(response.body(), Map.class);

        return Map.of(
                "request", Map.of("data", data, "encrypted", encrypted),
                "response", Map.of("data", responseMap.get("data"))
        );
    }

    @PostMapping("/response-only")
    public Map<String, Object> responseOnlyEcdhEncrypt(@RequestBody(required = false) PlainData plainData) throws Exception {
        String data = plainData == null || plainData.data() == null ? "Hello, World!" : plainData.data();

        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey sessionKey = keyGenerator.generateKey();
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);

        ClientSessionKeyTransport sessionTransport = ClientSessionKeyTransport.fromGeneratedKey(
                sessionKey,
                iv,
                null
        );

        HttpRequest request = buildSessionKeyRequest(
                serverBaseUri.resolve("/crypto/server/ecdh/response-only"),
                data,
                sessionTransport
        );

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("response-only ECDH encrypt request failed: status=" + response.statusCode() + ", body=" + response.body());
        }

        Map<String, Object> responsePayload = objectMapper.readValue(response.body(), Map.class);
        String encryptedDataBase64 = (String) responsePayload.get("encryptedDataBase64");
        String ivBase64 = (String) responsePayload.get("ivBase64");

        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(
                Cipher.DECRYPT_MODE,
                sessionKey,
                new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, EncodingUtils.fromBase64(ivBase64))
        );
        String decryptedResponseData = new String(
                aesCipher.doFinal(EncodingUtils.fromBase64(encryptedDataBase64)),
                StandardCharsets.UTF_8
        );

        return Map.of(
                "request", Map.of("data", data),
                "response", Map.of("data", decryptedResponseData, "encrypted", responsePayload)
        );
    }

    private HttpRequest buildSessionKeyRequest(URI endpoint, String data, ClientSessionKeyTransport sessionKeyTransport) throws Exception {
        return sessionKeyTransport.apply(HttpRequest.newBuilder(endpoint)
                        .header("Content-Type", "application/json"))
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(Map.of("data", data))))
                .build();
    }
}
