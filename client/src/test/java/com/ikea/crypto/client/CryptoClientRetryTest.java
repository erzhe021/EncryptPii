package com.ikea.crypto.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.client.api.CryptoClientController;
import com.ikea.crypto.client.constant.CryptoConstants;
import com.ikea.crypto.client.model.PublicKeyResponse;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyPairGenerator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
        ObjectMapper objectMapper = new ObjectMapper();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/crypto/server/public-key", exchange -> {
            int version = keyRequests.incrementAndGet();
            respond(exchange, 200, objectMapper.writeValueAsString(
                    new PublicKeyResponse(publicKey, "rsa-ciam:" + version, System.currentTimeMillis() + 60_000)));
        });
        server.createContext("/crypto/server/request-only", exchange -> {
            var payload = objectMapper.readTree(exchange.getRequestBody());
            requestKeyIds.add(payload.path("keyId").asText());
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
        } finally {
            server.stop(0);
        }
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
