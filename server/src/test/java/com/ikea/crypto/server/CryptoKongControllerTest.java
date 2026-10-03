package com.ikea.crypto.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.server.api.CryptoKongController;
import com.ikea.crypto.server.model.DemoSensitiveRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(CryptoKongController.class)
@TestPropertySource(properties = "sensitive.transport.crypto.kong-gateway-token=test-only-gateway-token")
class CryptoKongControllerTest {

    private static final String GATEWAY_TOKEN = "test-only-gateway-token";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void rejectsRequestsWithoutGatewayToken() throws Exception {
        mockMvc.perform(post("/crypto/kong/bidirectional")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new DemoSensitiveRequest("name", "phone", "email", "address"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void acceptsAuthenticatedPlaintextRequests() throws Exception {
        mockMvc.perform(post("/crypto/kong/bidirectional")
                        .header("X-Crypto-Gateway-Token", GATEWAY_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new DemoSensitiveRequest("name", "phone", "email", "address"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("name"))
                .andExpect(jsonPath("$.extraInfo").value("This is bidirectional encryption demo"));
    }
}
