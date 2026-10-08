package com.ikea.crypto.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.server.model.DemoPlainRequest;
import com.ikea.crypto.server.model.DemoSensitiveRequest;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.stc.crypto.SessionKeyService;
import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.model.CipherRequestBody;
import com.ikea.crypto.stc.model.SessionKeyTransport;
import com.ikea.crypto.stc.util.EncodingUtils;
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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(properties = "sensitive.transport.crypto.vault.enabled=false")
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
    void testServerHandlesMissingCryptoHeaders() throws Exception {
        mockMvc.perform(post("/crypto/server/bidirectional")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ivBase64\":\"iv\",\"encryptedDataBase64\":\"data\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_ENCRYPTED, "false"))
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").isNotEmpty());
    }

    @Test
    void testServerHandlesExpiredKeyDuringResponseEncryption() throws Exception {
        String staleKeyId = cryptoServer.keyRing().getKeyAlias() + ":0";
        mockMvc.perform(post("/crypto/server/response-only")
                        .header(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_KEY_ID, staleKeyId)
                        .header(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_SESSION_KEY, "AQID")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"data\":\"demo\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_ENCRYPTED, "false"))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.code").value("KEY_EXPIRED"))
                .andExpect(jsonPath("$.data.keyId").value(cryptoServer.getPublicKey().keyId()))
                .andExpect(jsonPath("$.data.publicKeyBase64").isNotEmpty());
    }

    @Test
    void testBidirectionalEndpoint() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey sessionKey = keyGenerator.generateKey();

        byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        String requestJson = objectMapper.writeValueAsString(
                new DemoSensitiveRequest("name", "1234567890", "demo@example.com", "Shanghai 123 Main St"));

        String encryptedData = AesGcmCipher.encryptAsBase64(requestJson, sessionKey, iv);
        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, cryptoServer.publicKey());

        CipherRequestBody requestPayload = new CipherRequestBody(EncodingUtils.toBase64(iv), encryptedData);

        mockMvc.perform(post("/crypto/server/bidirectional")
                        .header(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_KEY_ID,
                                cryptoServer.getPublicKey().keyId())
                        .header(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_SESSION_KEY, encryptedSessionKey)
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
        String requestJson = objectMapper.writeValueAsString(
                new DemoSensitiveRequest("name", "1234567890", "demo@example.com", "Shanghai 123 Main St"));

        String encryptedData = AesGcmCipher.encryptAsBase64(requestJson, sessionKey, iv);
        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, cryptoServer.publicKey());

        CipherRequestBody requestPayload = new CipherRequestBody(EncodingUtils.toBase64(iv), encryptedData);

        mockMvc.perform(post("/crypto/server/request-only")
                        .header(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_KEY_ID,
                                cryptoServer.getPublicKey().keyId())
                        .header(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_SESSION_KEY, encryptedSessionKey)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(requestPayload)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("0"))
                .andExpect(jsonPath("$.data").isNotEmpty());
    }

    @Test
    void testResponseOnlyEndpoint() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey sessionKey = keyGenerator.generateKey();

        SessionKeyTransport sessionTransport = SessionKeyTransport.fromGeneratedKey(sessionKey, cryptoServer.publicKey());

        DemoPlainRequest demoPlainRequest = new DemoPlainRequest("ping");

        mockMvc.perform(post("/crypto/server/response-only")
                        .header(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_KEY_ID,
                                cryptoServer.getPublicKey().keyId())
                        .header(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_SESSION_KEY, sessionTransport.encryptedSessionKeyBase64())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(demoPlainRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.encryptedDataBase64").isNotEmpty())
                .andExpect(jsonPath("$.ivBase64").isNotEmpty());
    }

    @Test
    void testResponseOnlyExceptionsRemainEncryptedWithoutGatewayToken() throws Exception {
        for (String variant : new String[]{"business-exception", "client-exception", "system-exception"}) {
            KeyGenerator generator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
            generator.init(CryptoConstants.AES_KEY_SIZE_BITS);
            SecretKey sessionKey = generator.generateKey();
            SessionKeyTransport transport = SessionKeyTransport.fromGeneratedKey(
                    cryptoServer.getPublicKey().keyId(), sessionKey, cryptoServer.publicKey());
            int expectedStatus = switch (variant) {
                case "client-exception" -> 400;
                case "system-exception" -> 500;
                default -> 200;
            };
            String response = mockMvc.perform(post("/crypto/server/response-only/" + variant)
                            .header(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_KEY_ID, transport.keyId())
                            .header(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_SESSION_KEY,
                                    transport.encryptedSessionKeyBase64())
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"data\":\"local-demo\"}"))
                    .andExpect(status().is(expectedStatus))
                    .andExpect(header().string(CryptoConstants.HEADER_SENSITIVE_TRANSPORT_CRYPTO_ENCRYPTED, "true"))
                    .andExpect(jsonPath("$.encryptedDataBase64").isNotEmpty())
                    .andReturn().getResponse().getContentAsString();
            var cipher = objectMapper.readTree(response);
            var plain = objectMapper.readTree(AesGcmCipher.decryptFromBase64(
                    cipher.get("encryptedDataBase64").asText(), sessionKey, cipher.get("ivBase64").asText()));
            if (expectedStatus == 200) {
                assertEquals("code-123", plain.get("code").asText());
            } else {
                assertEquals(expectedStatus, plain.get("status").asInt());
            }
        }
    }

//    @Test
//    void testRotateKeyDefaultAlias() throws Exception {
//        String content = mockMvc.perform(post("/crypto/server/rotate"))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$.publicKeyBase64").isNotEmpty())
//                .andExpect(jsonPath("$.keyId").isNotEmpty())
//                .andExpect(jsonPath("$.expiresAtEpochMillis").isNumber())
//                .andReturn().getResponse().getContentAsString();
//
//        PublicKeyResponse rotatedKey = objectMapper.readValue(content, PublicKeyResponse.class);
//        assertNotNull(rotatedKey.keyId());
//        assertTrue(rotatedKey.keyId().startsWith("ciam:"));
//
//        // Verify active key in /public-key endpoint is updated to newly rotated key
//        String activeContent = mockMvc.perform(get("/crypto/server/public-key"))
//                .andExpect(status().isOk())
//                .andReturn().getResponse().getContentAsString();
//        PublicKeyResponse activeKey = objectMapper.readValue(activeContent, PublicKeyResponse.class);
//        assertEquals(rotatedKey.keyId(), activeKey.keyId());
//    }
//
//    @Test
//    void testRotateKeyWithSpecifiedKeyAliasRequestParam() throws Exception {
//        String keyAlias = "param-key-" + UUID.randomUUID().toString().substring(0, 8);
//
//        // First rotation
//        String res1 = mockMvc.perform(post("/crypto/server/rotate").param("keyAlias", keyAlias))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$.publicKeyBase64").isNotEmpty())
//                .andReturn().getResponse().getContentAsString();
//        PublicKeyResponse key1 = objectMapper.readValue(res1, PublicKeyResponse.class);
//        assertTrue(key1.keyId().startsWith(keyAlias + ":"));
//        long v1 = Long.parseLong(key1.keyId().substring(keyAlias.length() + 1));
//
//        // Second rotation: version should increment by 1
//        String res2 = mockMvc.perform(post("/crypto/server/rotate").param("keyAlias", keyAlias))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$.keyId").value(keyAlias + ":" + (v1 + 1)))
//                .andReturn().getResponse().getContentAsString();
//        PublicKeyResponse key2 = objectMapper.readValue(res2, PublicKeyResponse.class);
//        assertEquals(keyAlias + ":" + (v1 + 1), key2.keyId());
//        assertNotEquals(key1.publicKeyBase64(), key2.publicKeyBase64());
//    }
//
//    @Test
//    void testRotateKeyWithRequestBody() throws Exception {
//        String keyAlias = "body-key-" + UUID.randomUUID().toString().substring(0, 8);
//        RotateKeyRequest request = new RotateKeyRequest(keyAlias);
//
//        String res = mockMvc.perform(post("/crypto/server/rotate")
//                        .contentType(MediaType.APPLICATION_JSON)
//                        .content(objectMapper.writeValueAsString(request)))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$.publicKeyBase64").isNotEmpty())
//                .andReturn().getResponse().getContentAsString();
//        PublicKeyResponse key = objectMapper.readValue(res, PublicKeyResponse.class);
//        assertTrue(key.keyId().startsWith(keyAlias + ":"));
//    }
//
//    @Test
//    void testRotateKeyWithPathVariable() throws Exception {
//        String keyAlias = "path-key-" + UUID.randomUUID().toString().substring(0, 8);
//
//        String res = mockMvc.perform(post("/crypto/server/rotate/" + keyAlias))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$.publicKeyBase64").isNotEmpty())
//                .andReturn().getResponse().getContentAsString();
//        PublicKeyResponse key = objectMapper.readValue(res, PublicKeyResponse.class);
//        assertTrue(key.keyId().startsWith(keyAlias + ":"));
//    }
//
//    @Test
//    void testRotationTransitionGracePeriodAfterEndpointCall() throws Exception {
//        String keyAlias = "grace-key-" + UUID.randomUUID().toString().substring(0, 8);
//
//        // 1. Initial key for grace-key
//        String v1Response = mockMvc.perform(post("/crypto/server/rotate").param("keyAlias", keyAlias))
//                .andExpect(status().isOk())
//                .andReturn().getResponse().getContentAsString();
//        PublicKeyResponse v1Key = objectMapper.readValue(v1Response, PublicKeyResponse.class);
//        long v1 = Long.parseLong(v1Key.keyId().substring(keyAlias.length() + 1));
//
//        KeyFactory kf = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA);
//        PublicKey pubKeyV1 = kf.generatePublic(new X509EncodedKeySpec(EncodingUtils.fromBase64(v1Key.publicKeyBase64())));
//
//        // 2. Client prepares encrypted message using v1 key
//        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
//        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
//        SecretKey sessionKey = keyGenerator.generateKey();
//        byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
//        String encryptedData = AesGcmCipher.encryptAsBase64("data-from-v1", sessionKey, iv);
//        String encryptedSessionKey = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, pubKeyV1);
//
//        // 3. Trigger rotation to v2 via API (must be v1 + 1 from Vault)
//        String v2Response = mockMvc.perform(post("/crypto/server/rotate").param("keyAlias", keyAlias))
//                .andExpect(status().isOk())
//                .andExpect(jsonPath("$.keyId").value(keyAlias + ":" + (v1 + 1)))
//                .andReturn().getResponse().getContentAsString();
//        PublicKeyResponse v2Key = objectMapper.readValue(v2Response, PublicKeyResponse.class);
//        PublicKey pubKeyV2 = kf.generatePublic(new X509EncodedKeySpec(EncodingUtils.fromBase64(v2Key.publicKeyBase64())));
//
//        // 4. Old client decrypts using v1 keyId
//        CipherRequestPayload oldPayload = new CipherRequestPayload(
//                v1Key.keyId(),
//                encryptedSessionKey,
//                EncodingUtils.toBase64(iv),
//                encryptedData
//        );
//        String decryptedOld = cryptoServer.decrypt(oldPayload);
//        assertEquals("data-from-v1", decryptedOld);
//
//        // 5. New client encrypts with v2 key and decrypts
//        SecretKey newSessionKey = keyGenerator.generateKey();
//        byte[] newIv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
//        String newEncData = AesGcmCipher.encryptAsBase64("data-from-v2", newSessionKey, newIv);
//        String newEncSessionKey = SessionKeyService.encryptSessionKeyAsBase64(newSessionKey, pubKeyV2);
//
//        CipherRequestPayload newPayload = new CipherRequestPayload(
//                v2Key.keyId(),
//                newEncSessionKey,
//                EncodingUtils.toBase64(newIv),
//                newEncData
//        );
//        String decryptedNew = cryptoServer.decrypt(newPayload);
//        assertEquals("data-from-v2", decryptedNew);
//    }
}
