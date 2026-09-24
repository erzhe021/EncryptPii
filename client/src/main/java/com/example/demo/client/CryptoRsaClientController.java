package com.example.demo.client;

import com.example.demo.crypto.*;
import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.crypto.rsa.RsaCryptoClient;
import com.example.demo.crypto.rsa.RsaHttpCryptoClient;
import com.example.demo.crypto.rsa.RsaPublicKeyResponse;
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
public class CryptoRsaClientController extends AbstractCryptoClientController {

    private final RsaCryptoClient rsaCryptoClient;

    public CryptoRsaClientController(@Value("${crypto.server.base-url:http://localhost:9090}") String serverBaseUrl) {
        super(serverBaseUrl);
        this.rsaCryptoClient = new RsaCryptoClient(new RsaHttpCryptoClient(serverBaseUri));
    }

    @PostMapping("/bidirectional")
    public Map<String, Object> bidirectionalRsaEncrypt(@RequestBody PlainData plainData) throws Exception {
        validatePlainData(plainData);
        RsaCipherPayload requestPayload = rsaCryptoClient.encrypt(toJsonString(plainData));
        HttpResponse<String> response = sendJsonRequest("/crypto/server/rsa/bidirectional", requestPayload);
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
        validatePlainData(plainData);
        RsaCipherPayload requestPayload = rsaCryptoClient.encrypt(toJsonString(plainData));
        Map<String, Object> responseMap = postForMap("/crypto/server/rsa/request-only", requestPayload, "request-only RSA encrypt");

        return Map.of(
                "request", Map.of("data", plainData.data(), "encrypted", requestPayload),
                "response", Map.of("data", responseMap.get("data"))
        );
    }

    @PostMapping("/response-only")
    public Map<String, Object> responseOnlyRsaEncrypt(@RequestBody(required = false) PlainData plainData)
            throws Exception {

        String data = plainData == null ? null : plainData.data();

        SecretKey sessionKey = generateSessionKey();
        byte[] iv = generateIv();

        PublicKey rsaPublicKey = loadServerRsaPublicKey();
        SessionKeyTransport sessionTransport = SessionKeyTransport.fromGeneratedKey(sessionKey, iv, rsaPublicKey);
        HttpResponse<String> response = httpClient.send(
                buildSessionKeyRequest(serverBaseUri.resolve("/crypto/server/rsa/response-only"), data, sessionTransport),
                HttpResponse.BodyHandlers.ofString()
        );
        ensureSuccess(response, "response-only RSA encrypt");

        DefaultAesCipherPayload responsePayload = objectMapper.readValue(response.body(), DefaultAesCipherPayload.class);

        String decryptedResponseData = decryptResponseData(responsePayload, sessionKey);
        PlainData responsePlainData = objectMapper.readValue(decryptedResponseData, PlainData.class);

        return Map.of(
                "request", Map.of("data", data == null ? "null" : data),
                "response", Map.of("data", responsePlainData.data(), "encrypted", responsePayload)
        );
    }

    private PublicKey loadServerRsaPublicKey() throws Exception {
        RsaPublicKeyResponse serverPublicKey = (RsaPublicKeyResponse) new RsaHttpCryptoClient(serverBaseUri).fetchServerPublicKey();
        return KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(serverPublicKey.publicKeyBase64()))
        );
    }
}
