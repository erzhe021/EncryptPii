package com.ikea.crypto.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.crypto.AesGcmCryptoService;
import com.ikea.crypto.common.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.crypto.SessionKeyService;
import com.ikea.crypto.common.model.demo.PlainData;
import com.ikea.crypto.common.model.demo.SensitiveData;
import com.ikea.crypto.common.model.payload.CipherRequestPayload;
import com.ikea.crypto.common.model.payload.SessionKeyTransport;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.server.service.CryptoServer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class CryptoServerControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CryptoServer cryptoServer;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void testGetPublicKeyEndpoint() throws Exception {
        mockMvc.perform(get("/crypto/server/public-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.publicKeyBase64").isNotEmpty())
                .andExpect(jsonPath("$.keyId").isNotEmpty());
    }

    @Test
    void testBidirectionalEndpoint() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey sessionKey = keyGenerator.generateKey();

        byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        String requestJson = objectMapper.writeValueAsString(new SensitiveData("secret message"));

        String encryptedData = AesGcmCryptoService.encryptAsBase64(requestJson, sessionKey, iv);
        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, cryptoServer.publicKey());

        CipherRequestPayload requestPayload = new CipherRequestPayload(
                encryptedSessionKey,
                EncodingUtils.toBase64(iv),
                encryptedData
        );

        mockMvc.perform(post("/crypto/server/bidirectional")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestPayload)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.encryptedDataBase64").isNotEmpty())
                .andExpect(jsonPath("$.ivBase64").isNotEmpty());
    }

    @Test
    void testRequestOnlyEndpoint() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey sessionKey = keyGenerator.generateKey();

        byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        String requestJson = objectMapper.writeValueAsString(new SensitiveData("plain response needed"));

        String encryptedData = AesGcmCryptoService.encryptAsBase64(requestJson, sessionKey, iv);
        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, cryptoServer.publicKey());

        CipherRequestPayload requestPayload = new CipherRequestPayload(
                encryptedSessionKey,
                EncodingUtils.toBase64(iv),
                encryptedData
        );

        mockMvc.perform(post("/crypto/server/request-only")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestPayload)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").value("mock plain response for request - plain response needed"));
    }

    @Test
    void testResponseOnlyEndpoint() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey sessionKey = keyGenerator.generateKey();

        SessionKeyTransport sessionTransport = SessionKeyTransport.fromGeneratedKey(sessionKey, cryptoServer.publicKey());

        PlainData plainRequest = new PlainData("ping");

        mockMvc.perform(post("/crypto/server/response-only")
                        .header(CryptoConstants.HEADER_ENCRYPTED_SESSION_KEY, sessionTransport.encryptedSessionKeyBase64())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(plainRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.encryptedDataBase64").isNotEmpty())
                .andExpect(jsonPath("$.ivBase64").isNotEmpty());
    }
}
