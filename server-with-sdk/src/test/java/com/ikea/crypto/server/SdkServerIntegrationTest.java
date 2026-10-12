package com.ikea.crypto.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.GcmIvGenerator;
import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.PublicKeyResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "spring.cloud.vault.enabled=false",
        "spring.cloud.vault.token=test-token",
        "sensitive.transport.crypto.vault.enabled=false"
})
@AutoConfigureMockMvc
class SdkServerIntegrationTest {

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper mapper;
    @Autowired private CryptoServer cryptoServer;

    private SecretKey sessionKey;
    private String wrappedKey;
    private String keyId;

    @BeforeEach
    void createSession() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        sessionKey = generator.generateKey();
        PublicKeyResponse publicKey = cryptoServer.getPublicKey();
        keyId = publicKey.keyId();
        Cipher rsa = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        rsa.init(Cipher.ENCRYPT_MODE, cryptoServer.keyRing().findKeyEntry(keyId).orElseThrow().publicKey());
        wrappedKey = Base64.getEncoder().encodeToString(rsa.doFinal(sessionKey.getEncoded()));
    }

    @Test
    void publicKeyEndpointIsRegisteredBySdkAutoConfiguration() throws Exception {
        mvc.perform(get("/sensitive-transport-crypto/public-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keyId").isNotEmpty())
                .andExpect(jsonPath("$.publicKeyBase64").isNotEmpty());
    }

    @Test
    void bidirectionalRequestRoundTripsThroughActualServerController() throws Exception {
        MvcResult result = mvc.perform(sessionRequest("/crypto/server/bidirectional")
                        .content(encryptRequest("""
                                {"name":"demo","phone":"123","email":"test@example.com","address":"demo"}
                                """)))
                .andExpect(status().isOk())
                .andExpect(header().string("X-STC-Encrypted", "true"))
                .andReturn();

        JsonNode plain = decryptResponse(result);
        assertEquals("0", plain.path("code").asText());
        assertEquals("demo", plain.path("data").path("name").asText());
    }

    @Test
    void requestOnlyResponseRemainsPlain() throws Exception {
        mvc.perform(sessionRequest("/crypto/server/request-only").content(encryptRequest("""
                        {"name":"demo","phone":"123","email":"test@example.com","address":"demo"}
                        """)))
                .andExpect(status().isOk())
                .andExpect(header().doesNotExist("X-STC-Encrypted"))
                .andExpect(jsonPath("$.data.name").value("demo"));
    }

    @Test
    void responseOnlyUsesHeaderKeyWithoutEncryptedRequestBody() throws Exception {
        MvcResult result = mvc.perform(sessionRequest("/crypto/server/response-only").content("{\"data\":\"demo\"}"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-STC-Encrypted", "true"))
                .andReturn();

        assertEquals("0", decryptResponse(result).path("code").asText());
    }

    @Test
    void responseOnlyBusinessErrorIsEncryptedEvenWithoutRequestBody() throws Exception {
        MvcResult result = mvc.perform(sessionRequest("/crypto/server/response-only/business-exception"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-STC-Encrypted", "true"))
                .andReturn();

        assertEquals("code-123", decryptResponse(result).path("code").asText());
    }

    @Test
    void missingHeadersAreRejected() throws Exception {
        mvc.perform(post("/crypto/server/response-only")
                        .contentType("application/json").content("{\"data\":\"demo\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("X-STC-Encrypted", "false"));
    }

    @Test
    void malformedSessionKeyProducesPlainCryptoError() throws Exception {
        mvc.perform(post("/crypto/server/response-only/client-exception")
                        .contentType("application/json")
                        .header("X-STC-Key-Id", keyId)
                        .header("X-STC-Session-Key", "not-base64!"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("X-STC-Encrypted", "false"))
                .andExpect(jsonPath("$.message").value("Invalid Base64 format in encrypted session key."));
    }

    @Test
    void invalidAesKeyLengthIsRejectedBeforeController() throws Exception {
        Cipher rsa = Cipher.getInstance(CryptoConstants.TRANSFORMATION_RSA);
        rsa.init(Cipher.ENCRYPT_MODE, cryptoServer.keyRing().findKeyEntry(keyId).orElseThrow().publicKey());
        wrappedKey = Base64.getEncoder().encodeToString(rsa.doFinal(new byte[8]));

        mvc.perform(sessionRequest("/crypto/server/response-only/business-exception"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("X-STC-Encrypted", "false"))
                .andExpect(jsonPath("$.message").value("Invalid AES session key length."));
    }

    @Test
    void applicationClientErrorResponseIsEncrypted() throws Exception {
        MvcResult result = mvc.perform(sessionRequest("/crypto/server/response-only/client-exception"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("X-STC-Encrypted", "true"))
                .andReturn();

        assertEquals(400, decryptResponse(result).path("status").asInt());
    }

    @Test
    void applicationServerErrorResponseIsEncrypted() throws Exception {
        MvcResult result = mvc.perform(sessionRequest("/crypto/server/response-only/system-exception"))
                .andExpect(status().isInternalServerError())
                .andExpect(header().string("X-STC-Encrypted", "true"))
                .andReturn();

        assertEquals(500, decryptResponse(result).path("status").asInt());
    }

    @Test
    void bodyKeyTransportIsRejected() throws Exception {
        mvc.perform(sessionRequest("/crypto/server/bidirectional")
                        .content("{\"ivBase64\":\"iv\",\"encryptedDataBase64\":\"data\",\"keyId\":\"test:1\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("X-STC-Encrypted", "false"));
    }

    @Test
    void coreDecryptionDoesNotRequireServletState() throws Exception {
        String plain = "{\"name\":\"demo\"}";
        CipherRequestPayload payload = mapper.readValue(encryptRequest(plain), CipherRequestPayload.class);

        assertEquals(plain, cryptoServer.decrypt(payload, sessionKey));
        assertArrayEquals(sessionKey.getEncoded(),
                cryptoServer.decryptSessionKeyToSecretKey(keyId, wrappedKey).getEncoded());
    }

    private MockHttpServletRequestBuilder sessionRequest(String endpoint) {
        return post(endpoint).contentType("application/json")
                .header("X-STC-Key-Id", keyId)
                .header("X-STC-Session-Key", wrappedKey);
    }

    private String encryptRequest(String plain) throws Exception {
        byte[] iv = GcmIvGenerator.generateIv();
        return mapper.writeValueAsString(new CipherRequestPayload(
                Base64.getEncoder().encodeToString(iv), AesGcmCipher.encryptAsBase64(plain, sessionKey, iv)));
    }

    private JsonNode decryptResponse(MvcResult result) throws Exception {
        JsonNode encrypted = mapper.readTree(result.getResponse().getContentAsString());
        assertEquals(2, encrypted.size());
        return mapper.readTree(AesGcmCipher.decryptFromBase64(
                encrypted.path("encryptedDataBase64").asText(), sessionKey, encrypted.path("ivBase64").asText()));
    }
}
