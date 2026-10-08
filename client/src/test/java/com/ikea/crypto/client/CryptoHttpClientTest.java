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
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

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
    void concurrentCacheMissesFetchThePublicKeyOnlyOnce() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        long expiresAt = System.currentTimeMillis() + 60_000;
        String response = "{\"publicKeyBase64\":\""
                + java.util.Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())
                + "\",\"keyId\":\"rsa-ciam:1\",\"expiresAtEpochMillis\":" + expiresAt + "}";
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/public-key", exchange -> {
            requests.incrementAndGet();
            respond(exchange, 200, response);
        });
        var executor = Executors.newFixedThreadPool(8);
        server.start();
        try {
            cryptoHttpClient = new CryptoHttpClient(
                    URI.create("http://127.0.0.1:" + server.getAddress().getPort()), "/public-key");
            CountDownLatch ready = new CountDownLatch(8);
            CountDownLatch start = new CountDownLatch(1);
            var results = new ArrayList<Future<CryptoHttpClient.ServerKeyInfo>>();
            for (int i = 0; i < 8; i++) {
                results.add(executor.submit(() -> {
                    ready.countDown();
                    if (!start.await(5, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Timed out waiting to start concurrent fetch");
                    }
                    return cryptoHttpClient.fetchServerKeyInfo();
                }));
            }
            assertTrue(ready.await(5, TimeUnit.SECONDS));
            start.countDown();
            for (var result : results) {
                var keyInfo = result.get(5, TimeUnit.SECONDS);
                assertEquals("rsa-ciam:1", keyInfo.keyId());
                assertEquals(keyPair.getPublic(), keyInfo.publicKey());
                assertEquals(expiresAt, keyInfo.expiresAtEpochMillis());
            }
            assertEquals(1, requests.get());
            assertEquals("rsa-ciam:1", cryptoHttpClient.fetchServerKeyInfo().keyId());
            assertEquals(1, requests.get());
        } finally {
            executor.shutdownNow();
            server.stop(0);
        }
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
            assertEquals("rsa-ciam:2", cryptoHttpClient.fetchServerKeyInfo().keyId());
            assertEquals(keyPair.getPublic(), cryptoHttpClient.fetchServerKeyInfo().publicKey());

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
                assertEquals("rsa-ciam:1", exchange.getRequestHeaders().getFirst("X-STC-Key-Id"));
                assertEquals("wrapped-session", exchange.getRequestHeaders().getFirst("X-STC-Session-Key"));
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
        respond(exchange, 400, body);
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, int statusCode, String body)
            throws IOException {
        byte[] response = body.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(statusCode, response.length);
        try (var responseBody = exchange.getResponseBody()) {
            responseBody.write(response);
        }
    }
}
