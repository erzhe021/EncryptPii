package com.example.demo.client;

import com.example.demo.crypto.*;
import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.crypto.rsa.RsaCryptoClient;
import com.example.demo.crypto.rsa.RsaHttpCryptoClient;
import com.example.demo.crypto.rsa.RsaPublicKeyResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.SecretKey;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

@RestController
@RequestMapping("/crypto/client/rsa")
@Slf4j
public class CryptoRsaClientController extends AbstractCryptoClientController {

    private final RsaCryptoClient rsaCryptoClient;
    private final String rsaPublicKeyPath;
    private final String rsaBidirectionalPath;
    private final String rsaRequestOnlyPath;
    private final String rsaResponseOnlyPath;

    public CryptoRsaClientController(
            @Value("${crypto.server.base-url:http://localhost:9090}") String serverBaseUrl,
            @Value("${crypto.server.endpoints.rsa.public-key:/crypto/server/rsa/public-key}") String rsaPublicKeyPath,
            @Value("${crypto.server.endpoints.rsa.bidirectional:/crypto/server/rsa/bidirectional}") String rsaBidirectionalPath,
            @Value("${crypto.server.endpoints.rsa.request-only:/crypto/server/rsa/request-only}") String rsaRequestOnlyPath,
            @Value("${crypto.server.endpoints.rsa.response-only:/crypto/server/rsa/response-only}") String rsaResponseOnlyPath
    ) {
        super(serverBaseUrl);
        this.rsaPublicKeyPath = rsaPublicKeyPath;
        this.rsaBidirectionalPath = rsaBidirectionalPath;
        this.rsaRequestOnlyPath = rsaRequestOnlyPath;
        this.rsaResponseOnlyPath = rsaResponseOnlyPath;
        this.rsaCryptoClient = new RsaCryptoClient(new RsaHttpCryptoClient(serverBaseUri, rsaPublicKeyPath));
    }

    @PostMapping("/bidirectional")
    public Map<String, Object> bidirectionalRsaEncrypt(@RequestBody PlainData plainData) throws Exception {
        log.info("Received bidirectional RSA encrypt request with data: {}", plainData.data());
        validatePlainData(plainData);
        RsaCipherPayload requestPayload = rsaCryptoClient.encrypt(toJsonString(plainData));
        HttpResponse<String> response = sendJsonRequest(rsaBidirectionalPath, requestPayload);
        ensureSuccess(response, "bidirectional RSA encrypt");
        RsaCipherPayload responsePayload = objectMapper.readValue(response.body(), RsaCipherPayload.class);
        String decryptedServerResponse = rsaCryptoClient.decrypt(responsePayload);
        PlainData responsePlainData = objectMapper.readValue(decryptedServerResponse, PlainData.class);

        return Map.of(
                "request", Map.of("data", plainData.data(), "encrypted", requestPayload),
                "response", Map.of("data", responsePlainData.data(), "encrypted", responsePayload)
        );
    }

    @PostMapping("/request-only")
    public Map<String, Object> requestOnlyRsaEncrypt(@RequestBody PlainData plainData) throws Exception {
        log.info("Received request-only RSA encrypt request with data: {}", plainData.data());
        validatePlainData(plainData);
        RsaCipherPayload requestPayload = rsaCryptoClient.encrypt(toJsonString(plainData));
        Map<String, Object> responseMap = postForMap(rsaRequestOnlyPath, requestPayload, "request-only RSA encrypt");

        return Map.of(
                "request", Map.of("data", plainData.data(), "encrypted", requestPayload),
                "response", Map.of("data", responseMap.get("data"))
        );
    }

    @PostMapping("/response-only")
    public Map<String, Object> responseOnlyRsaEncrypt(@RequestBody(required = false) PlainData plainData)
            throws Exception {
        log.info("Received response-only RSA encrypt request with data: {}", plainData == null ? "null" : plainData.data());
        String data = plainData == null ? null : plainData.data();

        // Generate a new session key and IV for AES encryption
        SecretKey sessionKey = generateSessionKey();
        byte[] iv = generateIv();

        PublicKey rsaPublicKey = loadServerRsaPublicKey();
        SessionKeyTransport sessionTransport = SessionKeyTransport.fromGeneratedKey(sessionKey, iv, rsaPublicKey);
        HttpResponse<String> response = httpClient.send(
                buildSessionKeyRequest(serverBaseUri.resolve(rsaResponseOnlyPath), data, sessionTransport),
                HttpResponse.BodyHandlers.ofString()
        );
        ensureSuccess(response, "response-only RSA encrypt");

        DefaultAesCipherPayload responsePayload = objectMapper.readValue(response.body(), DefaultAesCipherPayload.class);

        // Decrypt the response data using the session key and IV
        String decryptedResponseData = decryptResponseData(responsePayload, sessionKey);
        PlainData responsePlainData = objectMapper.readValue(decryptedResponseData, PlainData.class);

        return Map.of(
                "request", Map.of("data", data == null ? "null" : data),
                "response", Map.of("data", responsePlainData.data(), "encrypted", responsePayload)
        );
    }

    /**
     * Loads the server's RSA public key by fetching it from the server and converting it to a PublicKey object.
     *
     * @return the server's RSA public key
     * @throws Exception if an error occurs while fetching or converting the public key
     */
    private PublicKey loadServerRsaPublicKey() throws Exception {
        RsaPublicKeyResponse serverPublicKey =
                (RsaPublicKeyResponse) new RsaHttpCryptoClient(serverBaseUri, rsaPublicKeyPath).fetchServerPublicKey();
        return KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(serverPublicKey.publicKeyBase64()))
        );
    }
}
