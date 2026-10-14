package com.ikea.crypto.server;

import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.key.KeyRing;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.vault.core.VaultTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("memory")
class MemoryProfileIntegrationTest {

    @Autowired private MockMvc mvc;
    @Autowired private ApplicationContext context;
    @Autowired private CryptoServer cryptoServer;

    @Test
    void memoryProfileStartsWithoutVaultAndExposesConfiguredAlias() throws Exception {
        assertThat(context.getBeansOfType(VaultTemplate.class)).isEmpty();
        assertThat(cryptoServer.keyRing()).isExactlyInstanceOf(KeyRing.class);
        assertThat(cryptoServer.keyRing().getKeyAlias()).isEqualTo("demo-service");
        mvc.perform(get("/sensitive-transport-crypto/public-key/demo-service"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keyId").value(cryptoServer.getPublicKey("demo-service").keyId()))
                .andExpect(jsonPath("$.publicKeyBase64").isNotEmpty());
    }
}
