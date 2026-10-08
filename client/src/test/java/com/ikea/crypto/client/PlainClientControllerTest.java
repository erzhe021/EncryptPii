package com.ikea.crypto.client;

import com.ikea.crypto.client.api.PlainClientController;
import com.ikea.crypto.client.core.CryptoHttpClient;
import jakarta.servlet.ServletException;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class PlainClientControllerTest {

    private HttpServer kong;
    private MockMvc client;
    private String baseUrl;
    private final List<ReceivedRequest> requests = new CopyOnWriteArrayList<>();
    private static final String REQUEST = "{\"data\":\"demo\"}";
    private static final String RESPONSE =
            "{\"code\":\"0\",\"message\":null,\"data\":{\"cardNumber\":\"demo\",\"memberTier\":1,\"points\":10,\"remarks\":\"plain\"}}";

    private record ReceivedRequest(String path, String method, Map<String, List<String>> headers, String body) {
    }

    @BeforeEach
    void setUp() throws Exception {
        kong = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        kong.start();
        baseUrl = "http://127.0.0.1:" + kong.getAddress().getPort();
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new ClassPathResource("application.yml"));
        client = MockMvcBuilders.standaloneSetup(
                new PlainClientController(baseUrl,
                        yaml.getObject().getProperty("plain.server.endpoints.normal"))).build();
    }

    @AfterEach
    void tearDown() {
        kong.stop(0);
    }

    private void respondWith(int status, MediaType contentType, String body) {
        kong.createContext("/", exchange -> {
            requests.add(new ReceivedRequest(exchange.getRequestURI().getPath(),
                    exchange.getRequestMethod(), Map.copyOf(exchange.getRequestHeaders()),
                    new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            byte[] response = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", contentType.toString());
            exchange.sendResponseHeaders(status, response.length);
            try (var responseBody = exchange.getResponseBody()) {
                responseBody.write(response);
            }
        });
    }

    @Test
    void usesConfiguredUrlAndEndpoint() throws Exception {
        respondWith(200, MediaType.APPLICATION_JSON, RESPONSE);
        MockMvc customClient = MockMvcBuilders.standaloneSetup(
                new PlainClientController(baseUrl, "/custom/normal")).build();
        customClient.perform(post("/plain/client/normal")
                        .contentType(MediaType.APPLICATION_JSON).content(REQUEST))
                .andExpect(status().isOk());
        assertEquals(1, requests.size());
        assertEquals("/custom/normal", requests.get(0).path());
    }

    @Test
    void forwardsPlainRequestsWithoutEncryption() throws Exception {
        respondWith(200, MediaType.APPLICATION_JSON, RESPONSE);
        client.perform(post("/plain/client/normal")
                        .contentType(MediaType.APPLICATION_JSON).content(REQUEST))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.request.data").value("demo"))
                .andExpect(jsonPath("$.response.data.cardNumber").value("demo"))
                .andExpect(jsonPath("$.response.data.memberTier").value(1))
                .andExpect(jsonPath("$.response.data.points").value(10))
                .andExpect(jsonPath("$.response.data.remarks").value("plain"))
                .andExpect(jsonPath("$['latency in ms'].total").value(greaterThanOrEqualTo(0)))
                .andExpect(jsonPath("$['latency in ms'].http").value(greaterThanOrEqualTo(0)))
                .andExpect(jsonPath("$['latency in ms'].encryption").value(0))
                .andExpect(jsonPath("$['latency in ms'].decryption").value(0));
        assertEquals(1, requests.size());
        ReceivedRequest request = requests.get(0);
        assertEquals("/plain/server/normal", request.path());
        assertEquals("POST", request.method());
        assertEquals(REQUEST, request.body());
        assertTrue(request.headers().entrySet().stream().anyMatch(entry ->
                entry.getKey().equalsIgnoreCase("Content-Type")
                        && entry.getValue().equals(List.of(MediaType.APPLICATION_JSON_VALUE))));
        for (String header : new String[]{"X-STC-Key-Id", "X-STC-Session-Key", "X-Crypto-Gateway-Token"}) {
            assertTrue(request.headers().keySet().stream().noneMatch(header::equalsIgnoreCase));
        }
    }

    @Test
    void rejectsNon200UpstreamStatusLikeCryptoClient() {
        respondWith(201, MediaType.APPLICATION_JSON, RESPONSE);
        ServletException failure = assertThrows(ServletException.class,
                () -> client.perform(post("/plain/client/normal")
                        .contentType(MediaType.APPLICATION_JSON).content(REQUEST)));
        assertInstanceOf(CryptoHttpClient.HttpStatusException.class, failure.getCause());
        assertTrue(failure.getCause().getMessage().contains("status=201"));
        assertEquals(1, requests.size());
    }

    @Test
    void rejectsRemovedEndpoints() throws Exception {
        for (String endpoint : new String[]{"bidirectional", "request-only", "response-only"}) {
            client.perform(post("/plain/client/" + endpoint)
                            .contentType(MediaType.APPLICATION_JSON).content(REQUEST))
                    .andExpect(status().isNotFound());
        }
        assertTrue(requests.isEmpty());
    }

    @Test
    void surfacesUpstreamErrorsLikeCryptoClient() {
        respondWith(400, MediaType.APPLICATION_JSON, "{\"error\":\"invalid request\"}");
        ServletException failure = assertThrows(ServletException.class,
                () -> client.perform(post("/plain/client/normal")
                        .contentType(MediaType.APPLICATION_JSON).content(REQUEST)));
        assertInstanceOf(CryptoHttpClient.HttpStatusException.class, failure.getCause());
        assertTrue(failure.getCause().getMessage().contains("status=400"));
        assertTrue(failure.getCause().getMessage().contains("{\"error\":\"invalid request\"}"));
        assertEquals(1, requests.size());
    }

    @Test
    void surfacesNonJsonUpstreamErrorsLikeCryptoClient() {
        respondWith(502, MediaType.TEXT_PLAIN, "upstream unavailable");
        ServletException failure = assertThrows(ServletException.class,
                () -> client.perform(post("/plain/client/normal")
                        .contentType(MediaType.APPLICATION_JSON).content(REQUEST)));
        assertInstanceOf(CryptoHttpClient.HttpStatusException.class, failure.getCause());
        assertTrue(failure.getCause().getMessage().contains("status=502"));
        assertTrue(failure.getCause().getMessage().contains("upstream unavailable"));
        assertEquals(1, requests.size());
    }
}
