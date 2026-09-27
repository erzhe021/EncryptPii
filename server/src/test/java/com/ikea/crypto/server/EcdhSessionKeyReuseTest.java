package com.ikea.crypto.server;

import com.ikea.crypto.common.AesCipherPayload;
import com.ikea.crypto.common.CryptoConstants;
import com.ikea.crypto.common.EncodingUtils;
import com.ikea.crypto.common.core.AesGcmCryptoService;
import com.ikea.crypto.common.core.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.ecdh.*;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.service.EcdhCryptoServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import javax.crypto.SecretKey;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class EcdhSessionKeyReuseTest {

    private StringRedisTemplate redisTemplate;
    private ValueOperations<String, String> valueOperations;
    private final Map<String, String> redisStorage = new HashMap<>();
    private EcdhCryptoServer server;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() throws Exception {
        redisTemplate = Mockito.mock(StringRedisTemplate.class);
        valueOperations = Mockito.mock(ValueOperations.class);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        Mockito.doAnswer(inv -> {
            String key = inv.getArgument(0);
            String val = inv.getArgument(1);
            redisStorage.put(key, val);
            return null;
        }).when(valueOperations).set(anyString(), anyString(), any());

        when(valueOperations.get(anyString())).thenAnswer(inv -> {
            String key = inv.getArgument(0);
            return redisStorage.get(key);
        });

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyGen.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        KeyPair ecdsaKeyPair = keyGen.generateKeyPair();

        server = new EcdhCryptoServer(ecdsaKeyPair.getPrivate(), ecdsaKeyPair.getPublic(), redisTemplate);
    }

    @AfterEach
    void tearDown() {
        CryptoSessionContextAccessor.clearCryptoSessionContext();
    }

    @Test
    void testBidirectionalSessionKeyReuseAndFreshIv() throws Exception {
        // 1. Server publishes ephemeral public key
        EcdhEphemeralKeyResponse serverEphemeral = server.getEphemeralPublicKey();

        // 2. Client negotiates key and encrypts request
        KeyPair clientEphemeral = EcdhKeyPairFactory.generateEphemeralKeyPair();
        String clientPubBase64 = EncodingUtils.toBase64(clientEphemeral.getPublic().getEncoded());

        byte[] requestIv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        SecretKey clientSessionKey = EcdhKeyAgreementService.deriveAesKey(
                clientEphemeral.getPrivate(),
                KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC)
                        .generatePublic(new X509EncodedKeySpec(EncodingUtils.fromBase64(serverEphemeral.ephemeralPublicKeyBase64()))),
                requestIv,
                CryptoConstants.HKDF_INFO_REQUEST_AES_KEY
        );

        String requestPlaintext = "Hello Server!";
        String encryptedRequestData = AesGcmCryptoService.encryptAsBase64(requestPlaintext, clientSessionKey, requestIv);

        EcdhCipherPayload requestPayload = new EcdhCipherPayload(
                new EcdhHandshakeContext(clientPubBase64, serverEphemeral.ephemeralPublicKeyBase64()),
                new AesCipherPayload(EncodingUtils.toBase64(requestIv), encryptedRequestData)
        );

        // 3. Server decrypts request (loads private key from Redis once, derives sessionKey, caches in context)
        String decryptedRequest = server.decrypt(requestPayload);
        assertEquals(requestPlaintext, decryptedRequest);

        // 4. Server encrypts response (reuses cached sessionKey from context, does NOT query Redis or derive key)
        String responsePlaintext = "Hello Client!";
        EcdhCipherPayload responsePayload = server.encryptWithEcdhHandshakeContext(
                responsePlaintext,
                requestPayload.handshakeContext()
        );

        // Verify response IV is fresh and different from request IV
        assertNotEquals(EncodingUtils.toBase64(requestIv), responsePayload.aesCipherPayload().ivBase64());

        // 5. Client decrypts response directly using the same sessionKey and response's IV (no HKDF or ECDH)
        String decryptedResponse = AesGcmCryptoService.decryptFromBase64(
                responsePayload.aesCipherPayload().encryptedDataBase64(),
                clientSessionKey,
                responsePayload.aesCipherPayload().ivBase64()
        );
        assertEquals(responsePlaintext, decryptedResponse);

        // 6. Verify Redis was only queried ONCE during decrypt, and NEVER during response encryption
        Mockito.verify(valueOperations, Mockito.times(1)).get(anyString());
    }
}
