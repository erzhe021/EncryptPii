package com.example.demo.client;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.PlainData;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhCryptoClient;
import com.example.demo.crypto.ecdh.EcdhHttpCryptoClient;
import com.example.demo.crypto.ecdh.HkdfUtils;
import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.crypto.rsa.RsaCryptoClient;
import com.example.demo.crypto.rsa.RsaHttpCryptoClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

@RestController
@RequestMapping("/crypto/client")
public class CryptoClientController {

    private final URI serverBaseUri;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public CryptoClientController(@Value("${crypto.server.base-url:http://localhost:9090}") String serverBaseUrl) {
        this.serverBaseUri = URI.create(serverBaseUrl);
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
    }

    @PostMapping("/rsa/bidirectional")
    public Map<String, Object> bidirectionalRsaEncrypt(@RequestBody(required = false) PlainData plainData) throws Exception {

        String data = plainData == null || plainData.data() == null ? "Hello, World!" : plainData.data();
        String requestJson = objectMapper.writeValueAsString(Map.of("data", data));
        RsaCryptoClient cryptoClient = new RsaCryptoClient(new RsaHttpCryptoClient(serverBaseUri));
        RsaCipherPayload requestPayload = cryptoClient.encrypt(requestJson);

        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve("/crypto/server/rsa/bidirectional"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestPayload)))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("bidirectional RSA encrypt request failed: status=" + response.statusCode() + ", body=" + response.body());
        }

        RsaCipherPayload responsePayload = objectMapper.readValue(response.body(), RsaCipherPayload.class);
        String decryptedServerResponseJson = cryptoClient.decrypt(responsePayload);
        PlainData decryptedServerResponseData = objectMapper.readValue(decryptedServerResponseJson, PlainData.class);

        return Map.of(
                "request", Map.of("data", data, "encrypted", requestPayload),
                "response", Map.of("data", decryptedServerResponseData.data(), "encrypted", responsePayload)
        );
    }

    @PostMapping("/rsa/request-only")
    public Map<String, Object> requestOnlyRsaEncrypt(@RequestBody(required = false) PlainData plainData) throws Exception {

        String data = plainData == null || plainData.data() == null ? "Hello, World!" : plainData.data();
        String requestJson = objectMapper.writeValueAsString(Map.of("data", data));
        RsaCryptoClient cryptoClient = new RsaCryptoClient(new RsaHttpCryptoClient(serverBaseUri));
        RsaCipherPayload requestPayload = cryptoClient.encrypt(requestJson);

        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve("/crypto/server/rsa/request-only"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestPayload)))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("request-only RSA encrypt request failed: status=" + response.statusCode() + ", body=" + response.body());
        }

        Map<String, Object> responsePayload = objectMapper.readValue(response.body(), Map.class);

        return Map.of(
                "request", Map.of("data", data, "encrypted", requestPayload),
                "response", Map.of("data", responsePayload.get("data"))
        );
    }

    @PostMapping("/rsa/response-only")
    public Map<String, Object> responseOnlyRsaEncrypt(@RequestBody(required = false) PlainData plainData) throws Exception {

        String data = plainData == null || plainData.data() == null ? "Hello, World!" : plainData.data();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        Map<String, String> requestBody = Map.of(
                "data", data,
                "clientPublicKeyBase64", EncodingUtils.toBase64(keyPair.getPublic().getEncoded())
        );

        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve("/crypto/server/rsa/response-only"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestBody)))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("response-only RSA encrypt request failed: status=" + response.statusCode() + ", body=" + response.body());
        }

        RsaCipherPayload responsePayload = objectMapper.readValue(response.body(), RsaCipherPayload.class);
        Cipher rsaCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        rsaCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] aesKeyBytes = rsaCipher.doFinal(EncodingUtils.fromBase64(responsePayload.encryptedAesKeyBase64()));
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, CryptoConstants.ALGORITHM_AES);

        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(
                Cipher.DECRYPT_MODE,
                aesKey,
                new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, EncodingUtils.fromBase64(responsePayload.ivBase64()))
        );
        String decryptedResponseData = new String(
                aesCipher.doFinal(EncodingUtils.fromBase64(responsePayload.encryptedDataBase64())),
                StandardCharsets.UTF_8
        );

        return Map.of(
                "request", Map.of("data", data),
                "response", Map.of("data", decryptedResponseData, "encrypted", responsePayload)
        );
    }

    @PostMapping("/ecdh/bidirectional")
    public Map<String, Object> bidirectionalEcdhEncrypt(@RequestBody(required = false) PlainData plainData) throws Exception {
        String data = plainData == null || plainData.data() == null ? "Hello, World!" : plainData.data();
        String requestJson = objectMapper.writeValueAsString(Map.of("data", data));

        EcdhCryptoClient cryptoClient = new EcdhCryptoClient(new EcdhHttpCryptoClient(serverBaseUri));
        EcdhCipherPayload encrypted = cryptoClient.encrypt(requestJson);

        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve("/crypto/server/ecdh/bidirectional"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(encrypted)))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("bidirectional ECDH encrypt request failed: status=" + response.statusCode() + ", body=" + response.body());
        }

        EcdhCipherPayload responsePayload = objectMapper.readValue(response.body(), EcdhCipherPayload.class);
        String decryptedServerResponse = cryptoClient.decrypt(responsePayload);
        PlainData decryptedServerResponseData = objectMapper.readValue(decryptedServerResponse, PlainData.class);

        return Map.of(
                "request", Map.of("data", data, "encrypted", encrypted),
                "response", Map.of("data", decryptedServerResponseData.data(), "encrypted", responsePayload)
        );
    }

    @PostMapping("/ecdh/request-only")
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

    @PostMapping("/ecdh/response-only")
    public Map<String, Object> responseOnlyEcdhEncrypt(@RequestBody(required = false) PlainData plainData) throws Exception {
        String data = plainData == null || plainData.data() == null ? "Hello, World!" : plainData.data();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyPairGenerator.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Map<String, String> requestBody = Map.of(
                "data", data,
                "clientEphemeralPublicKeyBase64", EncodingUtils.toBase64(keyPair.getPublic().getEncoded())
        );

        HttpRequest request = HttpRequest.newBuilder(serverBaseUri.resolve("/crypto/server/ecdh/response-only"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(requestBody)))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("response-only ECDH encrypt request failed: status=" + response.statusCode() + ", body=" + response.body());
        }

        EcdhCipherPayload responsePayload = objectMapper.readValue(response.body(), EcdhCipherPayload.class);
        PublicKey serverPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(responsePayload.serverEphemeralPublicKeyBase64()))
        );
        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        keyAgreement.init(keyPair.getPrivate());
        keyAgreement.doPhase(serverPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        byte[] iv = EncodingUtils.fromBase64(responsePayload.ivBase64());
        byte[] derivedAesKey = HkdfUtils.deriveAesKey(
                sharedSecret,
                iv,
                CryptoConstants.HKDF_INFO_DATA_AES_KEY.getBytes(StandardCharsets.UTF_8),
                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
        );

        SecretKey aesKey = new SecretKeySpec(derivedAesKey, CryptoConstants.ALGORITHM_AES);
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
        String decryptedResponseData = new String(
                aesCipher.doFinal(EncodingUtils.fromBase64(responsePayload.encryptedDataBase64())),
                StandardCharsets.UTF_8
        );

        return Map.of(
                "request", Map.of("data", data),
                "response", Map.of("data", decryptedResponseData, "encrypted", responsePayload)
        );
    }
}
