package com.example.demo.server.crypto;

import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.server.crypto.ecdh.EcdhCryptoServer;
import com.example.demo.server.crypto.rsa.RsaCryptoServer;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class CryptoAdviceIntegrationTest {

    private static final Path TEST_KEY_DIR = createTempKeyDir();

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("rsa.crypto.key-directory", () -> TEST_KEY_DIR.resolve("rsa").toString());
        registry.add("ecdh.crypto.key-directory", () -> TEST_KEY_DIR.resolve("ecdh").toString());
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RsaCryptoServer rsaCryptoServer;

    @Autowired
    private EcdhCryptoServer ecdhCryptoServer;

    @Test
    void rsaAnnotatedEndpointShouldDecryptRequestAndEncryptResponse() throws Exception {
        RsaCipherPayload encryptedRequest = rsaCryptoServer.encrypt("{\"data\":\"13800138000\"}");

        String responseBody = mockMvc.perform(post("/api/secure/rsa/echo")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsBytes(encryptedRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.algorithm").value("RSA-OAEP + AES-256-GCM"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        RsaCipherPayload encryptedResponse = objectMapper.readValue(responseBody, RsaCipherPayload.class);
        String plainResponse = rsaCryptoServer.decrypt(encryptedResponse);
        assertEquals("{\"data\":\"RSA:13800138000\"}", plainResponse);
    }

    @Test
    void ecdhAnnotatedEndpointShouldDecryptRequestAndEncryptResponse() throws Exception {
        EcdhCipherPayload encryptedRequest = ecdhCryptoServer.encrypt("{\"data\":\"13900139000\"}");

        String responseBody = mockMvc.perform(post("/api/secure/ecdh/echo")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsBytes(encryptedRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.algorithm").value("ECDH-P256 + HKDF-SHA256 + AES-256-GCM"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        EcdhCipherPayload encryptedResponse = objectMapper.readValue(responseBody, EcdhCipherPayload.class);
        String plainResponse = ecdhCryptoServer.decrypt(encryptedResponse);
        assertEquals("{\"data\":\"ECDH:13900139000\"}", plainResponse);
    }

    @Test
    void invalidEncryptedRequestShouldReturnBadRequest() throws Exception {
        mockMvc.perform(post("/api/secure/rsa/echo")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"algorithm\":\"RSA-OAEP + AES-256-GCM\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error", startsWith("Encrypted AES key is required")));
    }

    private static Path createTempKeyDir() {
        try {
            return Files.createTempDirectory("crypto-advice-test");
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create test key directory", e);
        }
    }
}
