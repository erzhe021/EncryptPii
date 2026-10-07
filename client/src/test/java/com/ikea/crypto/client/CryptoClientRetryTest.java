package com.ikea.crypto.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.client.api.CryptoClientController;
import com.ikea.crypto.client.constant.CryptoConstants;
import com.ikea.crypto.client.crypto.SessionKeyService;
import com.ikea.crypto.client.model.CipherResponsePayload;
import com.ikea.crypto.client.model.PublicKeyResponse;
import com.ikea.crypto.client.util.EncodingUtils;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class CryptoClientRetryTest {

    @Test
    void refreshesThePublicKeyAndRetriesOnceForStaleKey() throws Exception {
        var keyGenerator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        keyGenerator.initialize(CryptoConstants.RSA_KEY_SIZE_BITS);
        String publicKey = java.util.Base64.getEncoder()
                .encodeToString(keyGenerator.generateKeyPair().getPublic().getEncoded());

        AtomicInteger keyRequests = new AtomicInteger();
        AtomicInteger encryptedRequests = new AtomicInteger();
        List<String> requestKeyIds = new CopyOnWriteArrayList<>();
        List<String> requestSessionKeys = new CopyOnWriteArrayList<>();
        ObjectMapper objectMapper = new ObjectMapper();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/crypto/server/public-key", exchange -> {
            int version = keyRequests.incrementAndGet();
            respond(exchange, 200, objectMapper.writeValueAsString(
                    new PublicKeyResponse(publicKey, "rsa-ciam:" + version, System.currentTimeMillis() + 60_000)));
        });
        server.createContext("/crypto/server/request-only", exchange -> {
            var payload = objectMapper.readTree(exchange.getRequestBody());
            requestKeyIds.add(exchange.getRequestHeaders().getFirst("X-STC-KEY-ID"));
            requestSessionKeys.add(exchange.getRequestHeaders().getFirst("X-STC-SESSION-KEY"));
            if (payload.size() != 2 || payload.has("keyId") || payload.has("encryptedSessionKeyBase64")) {
                respond(exchange, 400, "{\"code\":\"INVALID_BODY\"}");
                return;
            }
            if (encryptedRequests.incrementAndGet() == 1) {
                respond(exchange, 400, objectMapper.writeValueAsString(java.util.Map.of(
                        "code", "KEY_EXPIRED",
                        "msg", "密钥版本已过期，请更新公钥。最新公钥参考data",
                        "data", new PublicKeyResponse(publicKey, "rsa-ciam:2",
                                System.currentTimeMillis() + 60_000))));
            } else {
                respond(exchange, 200,
                        "{\"code\":\"0\",\"message\":null,\"data\":{\"cardNumber\":\"demo\",\"memberTier\":1,\"points\":10,\"remarks\":\"ok\"}}");
            }
        });
        server.start();
        try {
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            CryptoClientController controller = new CryptoClientController(
                    baseUrl,
                    "/crypto/server/public-key",
                    "/crypto/server/bidirectional",
                    "/crypto/server/request-only",
                    "/crypto/server/response-only");
            MockMvc client = MockMvcBuilders.standaloneSetup(controller).build();

            client.perform(post("/crypto/client/request-only")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"name\":\"demo\",\"phone\":\"123\",\"email\":\"demo@example.com\",\"address\":\"demo\"}"))
                    .andExpect(status().isOk());

            assertEquals(1, keyRequests.get());
            assertEquals(2, encryptedRequests.get());
            assertEquals(List.of("rsa-ciam:1", "rsa-ciam:2"), requestKeyIds);
            assertEquals(2, requestSessionKeys.size());
            assertNotEquals(requestSessionKeys.get(0), requestSessionKeys.get(1));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void allEncryptedModesRetryWithFreshSessionMaterialInHeaders() throws Exception {
        var keyGenerator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        keyGenerator.initialize(CryptoConstants.RSA_KEY_SIZE_BITS);
        KeyPair firstKey = keyGenerator.generateKeyPair();
        KeyPair secondKey = keyGenerator.generateKeyPair();
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, AtomicInteger> modeAttempts = new ConcurrentHashMap<>();
        List<String> keyIds = new CopyOnWriteArrayList<>();
        List<String> sessionHeaders = new CopyOnWriteArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            if (path.endsWith("/public-key")) {
                respond(exchange, 200, objectMapper.writeValueAsString(
                        new PublicKeyResponse(
                                java.util.Base64.getEncoder().encodeToString(firstKey.getPublic().getEncoded()),
                                "rsa-ciam:1", System.currentTimeMillis() + 60_000)));
                return;
            }
            int attempt = modeAttempts.computeIfAbsent(path, ignored -> new AtomicInteger()).incrementAndGet();
            String keyId = exchange.getRequestHeaders().getFirst("X-STC-KEY-ID");
            String encryptedSessionKey = exchange.getRequestHeaders().getFirst("X-STC-SESSION-KEY");
            keyIds.add(keyId);
            sessionHeaders.add(encryptedSessionKey);
            var body = objectMapper.readTree(exchange.getRequestBody());
            if (("/crypto/server/bidirectional".equals(path) || "/crypto/server/request-only".equals(path))
                    && (body.size() != 2 || body.has("keyId") || body.has("encryptedSessionKeyBase64"))) {
                    respond(exchange, 400, "{\"code\":\"INVALID_BODY\"}");
                    return;
                }

            if (attempt == 1) {
                respond(exchange, 400, objectMapper.writeValueAsString(Map.of(
                        "code", "KEY_EXPIRED",
                        "msg", "expired",
                        "data", new PublicKeyResponse(
                                java.util.Base64.getEncoder().encodeToString(secondKey.getPublic().getEncoded()),
                                "rsa-ciam:2", System.currentTimeMillis() + 60_000))));
                return;
            }
            var privateKey = "rsa-ciam:1".equals(keyId) ? firstKey.getPrivate() : secondKey.getPrivate();
            javax.crypto.SecretKey sessionKey;
            try {
                sessionKey = SessionKeyService.decryptSessionKeyBase64(encryptedSessionKey, privateKey);
            } catch (java.security.GeneralSecurityException failure) {
                exchange.close();
                throw new IllegalStateException(failure);
            }
            if ("/crypto/server/request-only".equals(path)) {
                respond(exchange, 200,
                        "{\"code\":\"0\",\"message\":null,\"data\":{\"cardNumber\":\"demo\",\"memberTier\":1,\"points\":10,\"remarks\":\"ok\"}}");
                return;
            }
            CipherResponsePayload encryptedResponse;
            try {
                encryptedResponse = encryptResponse(
                        "{\"code\":\"0\",\"message\":null,\"data\":{\"name\":\"name\",\"phone\":\"phone\",\"email\":\"email\",\"address\":\"address\",\"extraInfo\":\"ok\"}}",
                        sessionKey);
            } catch (Exception failure) {
                exchange.close();
                throw new IllegalStateException(failure);
            }
            respond(exchange, 200, objectMapper.writeValueAsString(encryptedResponse));
        });
        server.start();
        try {
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            String sensitiveRequest =
                    "{\"name\":\"demo\",\"phone\":\"123\",\"email\":\"demo@example.com\",\"address\":\"demo\"}";

            for (String mode : List.of("bidirectional", "request-only", "response-only")) {
                CryptoClientController controller = new CryptoClientController(
                        baseUrl,
                        "/crypto/server/public-key",
                        "/crypto/server/bidirectional",
                        "/crypto/server/request-only",
                        "/crypto/server/response-only");
                MockMvc client = MockMvcBuilders.standaloneSetup(controller).build();
                String body = "response-only".equals(mode) ? "{\"data\":\"demo\"}" : sensitiveRequest;
                client.perform(post("/crypto/client/" + mode)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                        .andExpect(status().isOk());
            }

            assertEquals(List.of("rsa-ciam:1", "rsa-ciam:2", "rsa-ciam:1",
                    "rsa-ciam:2", "rsa-ciam:1", "rsa-ciam:2"), keyIds);
            assertEquals(6, sessionHeaders.size());
            for (int attempt = 0; attempt < sessionHeaders.size(); attempt += 2) {
                assertNotEquals(sessionHeaders.get(attempt), sessionHeaders.get(attempt + 1));
            }
        } finally {
            server.stop(0);
        }
    }

    @Test
    void responseOnlyExceptionEndpointsDecryptErrorsAndRetryExpiredKeysOnce() throws Exception {
        var generator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        generator.initialize(CryptoConstants.RSA_KEY_SIZE_BITS);
        KeyPair key = generator.generateKeyPair();
        ObjectMapper mapper = new ObjectMapper();
        var publicKey = new PublicKeyResponse(
                EncodingUtils.toBase64(key.getPublic().getEncoded()),
                "rsa-ciam:2", System.currentTimeMillis() + 60_000);
        Map<String, AtomicInteger> attempts = new ConcurrentHashMap<>();
        Map<String, List<String>> sessions = new ConcurrentHashMap<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            if (path.endsWith("/public-key")) {
                respond(exchange, 200, mapper.writeValueAsString(new PublicKeyResponse(
                        publicKey.publicKeyBase64(), "rsa-ciam:1", publicKey.expiresAtEpochMillis())));
                return;
            }
            String variant = path.substring(path.lastIndexOf('/') + 1);
            String sessionHeader = exchange.getRequestHeaders().getFirst("X-STC-SESSION-KEY");
            sessions.computeIfAbsent(variant, ignored -> new CopyOnWriteArrayList<>()).add(sessionHeader);
            int attempt = attempts.computeIfAbsent(variant, ignored -> new AtomicInteger()).incrementAndGet();
            var request = mapper.readTree(exchange.getRequestBody());
            if (request != null && !request.isMissingNode()
                    && (request.size() != 1 || !"demo".equals(request.path("data").asText()))) {
                respond(exchange, 400, "{\"message\":\"invalid request body\"}");
                return;
            }
            if (attempt == 1) {
                respond(exchange, 400, mapper.writeValueAsString(
                        Map.of("code", "KEY_EXPIRED", "data", publicKey)));
                return;
            }
            if (!"rsa-ciam:2".equals(exchange.getRequestHeaders().getFirst("X-STC-KEY-ID"))) {
                respond(exchange, 400, "{\"message\":\"wrong key version\"}");
                return;
            }
            int status = switch (variant) {
                case "client-exception" -> 400;
                case "system-exception" -> 500;
                default -> 200;
            };
            String body = status == 200
                    ? "{\"code\":\"code-123\",\"message\":\"business error\",\"data\":null}"
                    : "{\"status\":" + status + ",\"message\":\"sensitive error\"}";
            try {
                var sessionKey = SessionKeyService.decryptSessionKeyBase64(sessionHeader, key.getPrivate());
                respond(exchange, status, mapper.writeValueAsString(encryptResponse(body, sessionKey)));
            } catch (Exception failure) {
                exchange.close();
                throw new IllegalStateException(failure);
            }
        });
        server.start();
        try {
            for (String variant : List.of("client-exception", "system-exception", "business-exception")) {
                CryptoClientController controller = new CryptoClientController(
                        "http://127.0.0.1:" + server.getAddress().getPort(),
                        "/crypto/server/public-key", "/crypto/server/bidirectional",
                        "/crypto/server/request-only", "/crypto/server/response-only");
                MockMvc client = MockMvcBuilders.standaloneSetup(controller).build();
                var request = post("/crypto/client/response-only/" + variant);
                if (!"business-exception".equals(variant)) {
                    request.contentType(MediaType.APPLICATION_JSON).content("{\"data\":\"demo\"}");
                }
                var response = client.perform(request).andExpect(status().isOk()).andReturn();
                var details = mapper.readTree(response.getResponse().getContentAsString());
                int expectedStatus = "client-exception".equals(variant) ? 400
                        : "system-exception".equals(variant) ? 500 : 200;
                assertEquals(expectedStatus, details.path("response").path("status").asInt());
                assertEquals("rsa-ciam:2", details.path("request").path("headers").path("X-STC-KEY-ID").asText());
                assertEquals(sessions.get(variant).get(1),
                        details.path("request").path("headers").path("X-STC-SESSION-KEY").asText());
                assertTrue(details.path("response").path("cipher").has("encryptedDataBase64"));
                assertEquals(expectedStatus == 200 ? "business error" : "sensitive error",
                        details.path("response").path("plain").path("message").asText());
                if (expectedStatus == 200) {
                    assertEquals("code-123", details.path("response").path("plain").path("code").asText());
                    assertEquals("no data", details.path("request").path("plain").asText());
                } else {
                    assertEquals("demo", details.path("request").path("plain").path("data").asText());
                }
                assertTrue(details.has("latency in ms"));
                assertEquals(2, attempts.get(variant).get());
                assertNotEquals(sessions.get(variant).get(0), sessions.get(variant).get(1));
            }
        } finally {
            server.stop(0);
        }
    }

    private static CipherResponsePayload encryptResponse(String plaintext, javax.crypto.SecretKey sessionKey)
            throws Exception {
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        new java.security.SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey,
                new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
        return new CipherResponsePayload(
                EncodingUtils.toBase64(iv),
                EncodingUtils.toBase64(cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8))));
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] response = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, response.length);
        try (var responseBody = exchange.getResponseBody()) {
            responseBody.write(response);
        }
    }
}
