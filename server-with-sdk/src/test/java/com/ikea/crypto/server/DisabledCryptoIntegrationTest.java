package com.ikea.crypto.server;

import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.vault.VaultKeySynchronizer;
import com.ikea.crypto.stc.web.advice.RequestDecryptAdvice;
import com.ikea.crypto.stc.web.advice.ResponseEncryptAdvice;
import com.ikea.crypto.stc.web.endpoint.PublicKeyEndpoint;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.vault.core.VaultTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "sensitive.transport.crypto.enabled=false",
        "spring.cloud.vault.uri=http://127.0.0.1:1"
})
@AutoConfigureMockMvc
class DisabledCryptoIntegrationTest {

    @Autowired private MockMvc mvc;
    @Autowired private ApplicationContext context;

    @Test
    void disabledServerRejectsEncryptionDeclarationsBeforeController() throws Exception {
        mvc.perform(post("/crypto/server/bidirectional")
                        .header("X-STC-Enabled", "true")
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("X-STC-Encrypted", "false"))
                .andExpect(jsonPath("$.message").value("Server transport crypto is disabled."));
    }

    @Test
    void disabledServerStillRejectsMalformedProtocolAndUndeclaredKeys() throws Exception {
        mvc.perform(post("/crypto/server/bidirectional").header("X-STC-Enabled", "invalid"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("X-STC-Encrypted", "false"));
        mvc.perform(post("/crypto/server/bidirectional").header("X-STC-Session-Key", "wrapped"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void disablingCryptoAlsoDisablesVaultAndServesPlaintext() throws Exception {
        assertThat(context.getEnvironment().getProperty("spring.cloud.vault.enabled", Boolean.class))
                .isFalse();
        assertThat(context.getBeansOfType(VaultTemplate.class)).isEmpty();
        assertThat(context.getBeansOfType(CryptoServer.class)).isEmpty();
        assertThat(context.getBeansOfType(VaultKeySynchronizer.class)).isEmpty();
        assertThat(context.getBeansOfType(RequestDecryptAdvice.class)).isEmpty();
        assertThat(context.getBeansOfType(ResponseEncryptAdvice.class)).isEmpty();
        assertThat(context.getBeansOfType(PublicKeyEndpoint.class)).isEmpty();
        mvc.perform(post("/crypto/server/bidirectional")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name":"Alice","phone":"123","email":"alice@example.com","address":"demo"}
                                """))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("X-STC-Encrypted"))
                .andExpect(jsonPath("$.data.name").value("Alice"))
                .andExpect(jsonPath("$.ivBase64").doesNotExist());
        mvc.perform(get("/sensitive-transport-crypto/public-key/demo-service"))
                .andExpect(status().isNotFound());
    }
}
