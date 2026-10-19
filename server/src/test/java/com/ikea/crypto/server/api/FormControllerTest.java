package com.ikea.crypto.server.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(value = CryptoController.class, properties = {
        "sensitive.transport.crypto.kong-gateway-token=test-gateway-token"
})
class FormControllerTest {
    @Autowired
    private MockMvc mvc;

    @Test
    void acceptsDecryptedFormAndKeepsFirstRepeatedValue() throws Exception {
        mvc.perform(post("/crypto/server/form-urlencoded")
                        .header("X-Crypto-Gateway-Token", "test-gateway-token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("name=Alice+Smith&name=Bob&phone=123%2B456"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("0"))
                .andExpect(jsonPath("$.data.name").value("Alice Smith"))
                .andExpect(jsonPath("$.data.remarks").value("form-urlencoded request-only crypto"));
    }

    @Test
    void rejectsFormWithoutGatewayAuthorization() throws Exception {
        mvc.perform(post("/crypto/server/form-urlencoded")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .content("name=Alice"))
                .andExpect(status().isForbidden());
    }
}
