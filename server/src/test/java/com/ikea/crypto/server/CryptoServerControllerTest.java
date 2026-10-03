package com.ikea.crypto.server;

import com.ikea.crypto.server.api.CryptoServerController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(CryptoServerController.class)
class CryptoServerControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void acceptsPlainNormalRequests() throws Exception {
        mockMvc.perform(post("/plain/server/normal")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"data\":\"demo\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cardNumber").value("123456789012"))
                .andExpect(jsonPath("$.memberTier").value(3))
                .andExpect(jsonPath("$.points").value(10000))
                .andExpect(jsonPath("$.remarks").value("remarks"));
    }

    @Test
    void rejectsMissingBody() throws Exception {
        mockMvc.perform(post("/plain/server/normal"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void rejectsRemovedPlainEndpoints() throws Exception {
        for (String endpoint : new String[]{"bidirectional", "request-only", "response-only"}) {
            mockMvc.perform(post("/plain/server/" + endpoint)
                            .contentType(MediaType.APPLICATION_JSON).content("{\"data\":\"demo\"}"))
                    .andExpect(status().isNotFound());
        }
    }

    @Test
    void removesOldServerMapping() throws Exception {
        mockMvc.perform(post("/crypto/server/bidirectional")
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isNotFound());
    }
}
