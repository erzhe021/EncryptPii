package com.ikea.crypto.client;

import com.ikea.crypto.client.api.PlainClientController;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestClient;

import java.util.Properties;

import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class PlainClientControllerTest {

    private MockRestServiceServer kong;
    private MockMvc client;
    private static final String REQUEST = "{\"data\":\"demo\"}";

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        kong = MockRestServiceServer.bindTo(builder).build();
        YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
        yaml.setResources(new ClassPathResource("application.yml"));
        Properties config = yaml.getObject();
        client = MockMvcBuilders.standaloneSetup(
                new PlainClientController(builder, "http://kong:8000",
                        config.getProperty("plain.server.endpoints.normal")
                )).build();
    }

    @Test
    void usesConfiguredUrlAndEndpoint() throws Exception {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer customKong = MockRestServiceServer.bindTo(builder).build();
        MockMvc customClient = MockMvcBuilders.standaloneSetup(
                new PlainClientController(builder, "http://custom-kong:9000",
                        "/custom/normal")).build();
        customKong.expect(requestTo("http://custom-kong:9000/custom/normal"))
                .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));
        customClient.perform(post("/plain/client/normal")
                        .contentType(MediaType.APPLICATION_JSON).content(REQUEST))
                .andExpect(status().isOk());
        customKong.verify();
    }

    @Test
    void forwardsPlainRequestsWithoutEncryption() throws Exception {
        kong.expect(requestTo("http://kong:8000/plain/server/normal"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().json(REQUEST))
                .andExpect(headerDoesNotExist("X-STC-KEY-ID"))
                .andExpect(headerDoesNotExist("X-STC-SESSION-KEY"))
                .andExpect(headerDoesNotExist("X-Crypto-Gateway-Token"))
                .andRespond(withSuccess("{\"result\":\"plain\"}", MediaType.APPLICATION_JSON));
        client.perform(post("/plain/client/normal")
                        .contentType(MediaType.APPLICATION_JSON).content(REQUEST))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value("plain"));
        kong.verify();
    }

    @Test
    void rejectsRemovedEndpoints() throws Exception {
        for (String endpoint : new String[]{"bidirectional", "request-only", "response-only"}) {
            client.perform(post("/plain/client/" + endpoint)
                            .contentType(MediaType.APPLICATION_JSON).content(REQUEST))
                    .andExpect(status().isNotFound());
        }
        kong.verify();
    }

    @Test
    void forwardsUpstreamErrorsUnchanged() throws Exception {
        kong.expect(requestTo("http://kong:8000/plain/server/normal"))
                .andExpect(content().json(REQUEST))
                .andRespond(withStatus(HttpStatus.BAD_REQUEST)
                        .contentType(MediaType.APPLICATION_JSON).body("{\"error\":\"invalid request\"}"));
        client.perform(post("/plain/client/normal")
                        .contentType(MediaType.APPLICATION_JSON).content(REQUEST))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid request"));
        kong.verify();
    }
}
