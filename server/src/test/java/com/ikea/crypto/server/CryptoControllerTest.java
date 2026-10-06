package com.ikea.crypto.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.server.api.CryptoController;
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

@WebMvcTest(CryptoController.class)
@TestPropertySource(properties = "sensitive.transport.crypto.kong-gateway-token=test-only-gateway-token")
class CryptoControllerTest {

    private static final String GATEWAY_TOKEN = "test-only-gateway-token";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void rejectsRequestsWithoutGatewayToken() throws Exception {
        mockMvc.perform(post("/crypto/server/bidirectional")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new DemoSensitiveRequest("name", "phone", "email", "address"))))
                .andExpect(status().isForbidden());
    }

    @Test
    void acceptsOtherAuthenticatedServerEndpoints() throws Exception {
        mockMvc.perform(post("/crypto/server/request-only")
                        .header("X-Crypto-Gateway-Token", GATEWAY_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new DemoSensitiveRequest("name", "phone", "email", "address"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cardNumber").value("1234-5678-9012-3456"));
        mockMvc.perform(post("/crypto/server/response-only")
                        .header("X-Crypto-Gateway-Token", GATEWAY_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("张三"));
    }

    @Test
    void acceptsAuthenticatedPlaintextRequests() throws Exception {
        mockMvc.perform(post("/crypto/server/bidirectional")
                        .header("X-Crypto-Gateway-Token", GATEWAY_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(
                                new DemoSensitiveRequest("name", "phone", "email", "address"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("name"))
                .andExpect(jsonPath("$.extraInfo").value("This is bidirectional encryption demo"));
    }
}
