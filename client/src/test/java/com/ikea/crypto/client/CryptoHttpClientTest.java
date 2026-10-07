package com.ikea.crypto.client;

import com.ikea.crypto.client.core.CryptoHttpClient;
import com.ikea.crypto.client.constant.CryptoConstants;
import com.ikea.crypto.client.model.CipherRequestPayload;
import com.ikea.crypto.client.model.SessionKeyTransport;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

class CryptoHttpClientTest {

    private CryptoHttpClient cryptoHttpClient;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        keyGen.initialize(CryptoConstants.RSA_KEY_SIZE_BITS);
        keyPair = keyGen.generateKeyPair();
    }

    @Test
    void testConstruct() {
        cryptoHttpClient = new CryptoHttpClient(URI.create("http:/localhost:9090"), "/crypto/server/public-key");
        assertNotNull(cryptoHttpClient);
    }

    @Test
    void recognizesOnlyTheExplicitStaleKeyError() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/stale-key", exchange -> respond(exchange,
                "{\"code\":\"KEY_EXPIRED\",\"msg\":\"expired\",\"data\":{\"publicKeyBase64\":\""
                        + java.util.Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())
                        + "\",\"keyId\":\"rsa-ciam:2\",\"expiresAtEpochMillis\":"
                        + (System.currentTimeMillis() + 60_000) + "}}"));
        server.createContext("/invalid-alias", exchange -> respond(exchange,
                "{\"code\":\"INVALID_KEY\",\"msg\":\"invalid alias\"}"));
        server.start();
        try {
            cryptoHttpClient = new CryptoHttpClient(
                    URI.create("http://127.0.0.1:" + server.getAddress().getPort()),
                    "/crypto/server/public-key");
            CipherRequestPayload payload = new CipherRequestPayload("iv", "data");
            SessionKeyTransport session = new SessionKeyTransport("key:1", "session");

            CryptoHttpClient.HttpStatusException expiredFailure = assertThrows(
                    CryptoHttpClient.HttpStatusException.class,
                    () -> cryptoHttpClient.postRequestOnly("/stale-key", payload, session));
            assertEquals("rsa-ciam:2",
                    cryptoHttpClient.getRefreshedKeyFromFailure(expiredFailure).keyId());

            CryptoHttpClient.HttpStatusException aliasFailure = assertThrows(
                    CryptoHttpClient.HttpStatusException.class,
                    () -> cryptoHttpClient.postRequestOnly("/invalid-alias", payload, session));
            assertNull(cryptoHttpClient.getRefreshedKeyFromFailure(aliasFailure));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void sendsCiphertextBodyAndSessionMaterialOnlyInHeaders() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/encrypted", exchange -> {
            try {
                var body = new ObjectMapper().readTree(exchange.getRequestBody());
                assertEquals(2, body.size());
                assertEquals("iv-value", body.path("ivBase64").asText());
                assertEquals("cipher-value", body.path("encryptedDataBase64").asText());
                assertNull(body.get("keyId"));
                assertNull(body.get("encryptedSessionKeyBase64"));
                assertEquals("rsa-ciam:1", exchange.getRequestHeaders().getFirst("X-STC-KEY-ID"));
                assertEquals("wrapped-session", exchange.getRequestHeaders().getFirst("X-STC-SESSION-KEY"));
                byte[] response = "{\"code\":\"0\",\"message\":null,\"data\":{}}"
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, response.length);
                try (var output = exchange.getResponseBody()) {
                    output.write(response);
                }
            } catch (AssertionError failure) {
                exchange.close();
                throw failure;
            }
        });
        server.start();
        try {
            cryptoHttpClient = new CryptoHttpClient(URI.create(
                    "http://127.0.0.1:" + server.getAddress().getPort()));
            cryptoHttpClient.postRequestOnly("/encrypted",
                    new CipherRequestPayload("iv-value", "cipher-value"),
                    new SessionKeyTransport("rsa-ciam:1", "wrapped-session"));
        } finally {
            server.stop(0);
        }
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, String body) throws IOException {
        byte[] response = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(400, response.length);
        try (var responseBody = exchange.getResponseBody()) {
            responseBody.write(response);
        }
    }
}
