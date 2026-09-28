package com.ikea.crypto.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.common.crypto.KeyAgreementService;
import com.ikea.crypto.common.crypto.KeyPairFactory;
import com.ikea.crypto.common.model.*;
import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.common.model.demo.PlainData;
import com.ikea.crypto.common.model.demo.SensitiveData;
import com.ikea.crypto.common.crypto.AesGcmCipher;
import com.ikea.crypto.common.crypto.CryptoSessionMaterialFactory;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class CryptoServerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void testBidirectionalFlow() throws Exception {
        // 1. Fetch ephemeral and ecdsa public keys
        MvcResult ephemeralResult = mockMvc.perform(get("/crypto/server/ecdh/ephemeral-public-key"))
                .andExpect(status().isOk())
                .andReturn();
        EphemeralKeyResponse ephemeralResponse = objectMapper.readValue(
                ephemeralResult.getResponse().getContentAsString(),
                EphemeralKeyResponse.class
        );

        // 2. Client derives keys
        KeyPair clientKeyPair = KeyPairFactory.generateEphemeralKeyPair();
        String clientPubBase64 = EncodingUtils.toBase64(clientKeyPair.getPublic().getEncoded());
        byte[] sharedSecret = KeyAgreementService.deriveSharedSecret(
                clientKeyPair.getPrivate(),
                KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC)
                        .generatePublic(new X509EncodedKeySpec(EncodingUtils.fromBase64(ephemeralResponse.ephemeralPublicKeyBase64())))
        );

        byte[] requestIv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        SecretKey requestKey = KeyAgreementService.deriveAesKey(
                sharedSecret,
                requestIv,
                CryptoConstants.HKDF_INFO_REQUEST_AES_KEY
        );

        String requestJson = objectMapper.writeValueAsString(new SensitiveData("hello-server"));
        String encryptedRequestData = AesGcmCipher.encryptAsBase64(requestJson, requestKey, requestIv);

        CipherRequestPayload requestPayload = new CipherRequestPayload(
                new HandshakeContext(clientPubBase64, ephemeralResponse.serverKeyTicketBase64()),
                new CipherDataPayload(EncodingUtils.toBase64(requestIv), encryptedRequestData)
        );

        // 3. Post to bidirectional
        MvcResult postResult = mockMvc.perform(post("/crypto/server/ecdh/bidirectional")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestPayload)))
                .andExpect(status().isOk())
                .andReturn();

        CipherDataPayload responseCipher = objectMapper.readValue(
                postResult.getResponse().getContentAsString(),
                CipherDataPayload.class
        );

        // 4. Client decrypts response
        byte[] responseIv = EncodingUtils.fromBase64(responseCipher.ivBase64());
        SecretKey responseKey = KeyAgreementService.deriveAesKey(
                sharedSecret,
                responseIv,
                CryptoConstants.HKDF_INFO_RESPONSE_AES_KEY
        );

        String decryptedResponseJson = AesGcmCipher.decryptFromBase64(
                responseCipher.encryptedDataBase64(),
                responseKey,
                responseCipher.ivBase64()
        );

        SensitiveData responseData = objectMapper.readValue(decryptedResponseJson, SensitiveData.class);
        assertEquals("mock ecdh response for request - hello-server", responseData.data());
    }

    @Test
    void testRequestOnlyFlow() throws Exception {
        MvcResult ephemeralResult = mockMvc.perform(get("/crypto/server/ecdh/ephemeral-public-key"))
                .andExpect(status().isOk())
                .andReturn();
        EphemeralKeyResponse ephemeralResponse = objectMapper.readValue(
                ephemeralResult.getResponse().getContentAsString(),
                EphemeralKeyResponse.class
        );

        KeyPair clientKeyPair = KeyPairFactory.generateEphemeralKeyPair();
        String clientPubBase64 = EncodingUtils.toBase64(clientKeyPair.getPublic().getEncoded());
        byte[] sharedSecret = KeyAgreementService.deriveSharedSecret(
                clientKeyPair.getPrivate(),
                KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC)
                        .generatePublic(new X509EncodedKeySpec(EncodingUtils.fromBase64(ephemeralResponse.ephemeralPublicKeyBase64())))
        );

        byte[] requestIv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        SecretKey requestKey = KeyAgreementService.deriveAesKey(
                sharedSecret,
                requestIv,
                CryptoConstants.HKDF_INFO_REQUEST_AES_KEY
        );

        String requestJson = objectMapper.writeValueAsString(new SensitiveData("hello-request-only"));
        String encryptedRequestData = AesGcmCipher.encryptAsBase64(requestJson, requestKey, requestIv);

        CipherRequestPayload requestPayload = new CipherRequestPayload(
                new HandshakeContext(clientPubBase64, ephemeralResponse.serverKeyTicketBase64()),
                new CipherDataPayload(EncodingUtils.toBase64(requestIv), encryptedRequestData)
        );

        MvcResult postResult = mockMvc.perform(post("/crypto/server/ecdh/request-only")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestPayload)))
                .andExpect(status().isOk())
                .andReturn();

        PlainData plainResponse = objectMapper.readValue(
                postResult.getResponse().getContentAsString(),
                PlainData.class
        );
        assertEquals("mock plain response for request - hello-request-only", plainResponse.data());
    }

    @Test
    void testResponseOnlyFlow() throws Exception {
        MvcResult ephemeralResult = mockMvc.perform(get("/crypto/server/ecdh/ephemeral-public-key"))
                .andExpect(status().isOk())
                .andReturn();
        EphemeralKeyResponse ephemeralResponse = objectMapper.readValue(
                ephemeralResult.getResponse().getContentAsString(),
                EphemeralKeyResponse.class
        );

        KeyPair clientKeyPair = KeyPairFactory.generateEphemeralKeyPair();
        String clientPubBase64 = EncodingUtils.toBase64(clientKeyPair.getPublic().getEncoded());

        PlainRequestPayload requestPayload = new PlainRequestPayload(
                new HandshakeContext(clientPubBase64, ephemeralResponse.serverKeyTicketBase64()),
                "hello-response-only"
        );

        MvcResult postResult = mockMvc.perform(post("/crypto/server/ecdh/response-only")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestPayload)))
                .andExpect(status().isOk())
                .andReturn();

        CipherDataPayload responseCipher = objectMapper.readValue(
                postResult.getResponse().getContentAsString(),
                CipherDataPayload.class
        );

        byte[] sharedSecret = KeyAgreementService.deriveSharedSecret(
                clientKeyPair.getPrivate(),
                KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC)
                        .generatePublic(new X509EncodedKeySpec(EncodingUtils.fromBase64(ephemeralResponse.ephemeralPublicKeyBase64())))
        );

        byte[] responseIv = EncodingUtils.fromBase64(responseCipher.ivBase64());
        SecretKey responseKey = KeyAgreementService.deriveAesKey(
                sharedSecret,
                responseIv,
                CryptoConstants.HKDF_INFO_RESPONSE_AES_KEY
        );

        String decryptedResponseJson = AesGcmCipher.decryptFromBase64(
                responseCipher.encryptedDataBase64(),
                responseKey,
                responseCipher.ivBase64()
        );

        PlainData plainResponse = objectMapper.readValue(decryptedResponseJson, PlainData.class);
        assertEquals("mock ecdh response for request - hello-response-only", plainResponse.data());
    }
}
