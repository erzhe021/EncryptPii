package com.ikea.crypto.server;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "sensitive.transport.crypto.enabled=true",
        "sensitive.transport.crypto.key-store=memory",
        "spring.cloud.vault.enabled=false"
})
@AutoConfigureMockMvc
class TransportHeaderIntegrationTest {
    @Autowired private MockMvc mvc;

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"false", "FALSE"})
    void absentOrFalseHeaderBypassesBothAnnotations(String enabled) throws Exception {
        for (String path : new String[] {"bidirectional", "request-only", "response-only"}) {
            MockHttpServletRequestBuilder request = post("/crypto/server/" + path)
                    .contentType("application/json")
                    .content("""
                            {"name":"Alice","phone":"123","email":"alice@example.com","address":"demo","data":"hello"}
                            """);
            if (enabled != null) {
                request.header("X-STC-Enabled", enabled);
            }
            mvc.perform(request)
                    .andExpect(status().isOk())
                    .andExpect(header().doesNotExist("X-STC-Encrypted"))
                    .andExpect(jsonPath("$.code").value("0"))
                    .andExpect(jsonPath("$.ivBase64").doesNotExist());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "yes", "1", "true,false", "true,true", " true "})
    void invalidEnableHeaderIsRejectedBeforeBusinessCode(String enabled) throws Exception {
        mvc.perform(post("/crypto/server/response-only")
                        .header("X-STC-Enabled", enabled)
                        .contentType("application/json").content("{\"data\":\"hello\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("X-STC-Encrypted", "false"))
                .andExpect(jsonPath("$.message").value("X-STC-Enabled must be a single true or false value."));
    }

    @Test
    void duplicateEnableHeadersAreRejected() throws Exception {
        mvc.perform(post("/crypto/server/response-only")
                        .header("X-STC-Enabled", "true", "true"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/crypto/server/response-only")
                        .header("X-STC-Enabled", "true", "false"))
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"false"})
    void plaintextDeclarationRejectsAnySessionKeyHeader(String enabled) throws Exception {
        for (String keyHeader : new String[] {"X-STC-Key-Id", "X-STC-Session-Key"}) {
            MockHttpServletRequestBuilder request = post("/crypto/server/bidirectional")
                    .header(keyHeader, "");
            if (enabled != null) {
                request.header("X-STC-Enabled", enabled);
            }
            mvc.perform(request)
                    .andExpect(status().isBadRequest())
                    .andExpect(header().string("X-STC-Encrypted", "false"))
                    .andExpect(jsonPath("$.message").value("Session key headers require X-STC-Enabled: true."));
        }
    }

    @Test
    void explicitEncryptionOnUnannotatedEndpointIsRejected() throws Exception {
        mvc.perform(post("/plain/server/normal").header("X-STC-Enabled", "true")
                        .contentType("application/json").content("{\"data\":\"hello\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Endpoint does not support transport crypto."));
    }

    @Test
    void duplicateSessionHeadersAreRejected() throws Exception {
        mvc.perform(post("/crypto/server/response-only").header("X-STC-Enabled", "true")
                        .header("X-STC-Key-Id", "demo:1", "demo:1")
                        .header("X-STC-Session-Key", "wrapped"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("X-STC-Key-Id must have exactly one non-blank value."));
    }

    @Test
    void plaintextBusinessErrorsRemainPlain() throws Exception {
        mvc.perform(post("/crypto/server/response-only/system-exception")
                        .contentType("application/json").content("{\"data\":\"hello\"}"))
                .andExpect(status().isInternalServerError())
                .andExpect(header().doesNotExist("X-STC-Encrypted"))
                .andExpect(jsonPath("$.status").value(500));
    }
}
