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
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class EcdhDirectionalKeyIsolationTest {

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
    void testDirectionalKeyIsolationWithSharedSecretReuse() throws Exception {
        // 1. Server publishes ephemeral public key
        EcdhEphemeralKeyResponse serverEphemeral = server.getEphemeralPublicKey();

        // 2. Client negotiates key pair and derives sharedSecret
        KeyPair clientEphemeral = EcdhKeyPairFactory.generateEphemeralKeyPair();
        String clientPubBase64 = EncodingUtils.toBase64(clientEphemeral.getPublic().getEncoded());

        byte[] clientSharedSecret = EcdhKeyAgreementService.deriveSharedSecret(
                clientEphemeral.getPrivate(),
                KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC)
                        .generatePublic(new X509EncodedKeySpec(EncodingUtils.fromBase64(serverEphemeral.ephemeralPublicKeyBase64())))
        );

        // Client derives client-write-key (request key)
        byte[] requestIv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        SecretKey clientRequestKey = EcdhKeyAgreementService.deriveAesKey(
                clientSharedSecret,
                requestIv,
                CryptoConstants.HKDF_INFO_REQUEST_AES_KEY
        );

        String requestPlaintext = "Client payload";
        String encryptedRequestData = AesGcmCryptoService.encryptAsBase64(requestPlaintext, clientRequestKey, requestIv);

        EcdhCipherPayload requestPayload = new EcdhCipherPayload(
                new EcdhHandshakeContext(clientPubBase64, serverEphemeral.ephemeralPublicKeyBase64()),
                new AesCipherPayload(EncodingUtils.toBase64(requestIv), encryptedRequestData)
        );

        // 3. Server decrypts request: calculates sharedSecret, caches it in context, derives request key and decrypts
        String decryptedRequest = server.decrypt(requestPayload);
        assertEquals(requestPlaintext, decryptedRequest);

        // 4. Server encrypts response: reuses sharedSecret from context, derives response key (server-write-key)
        String responsePlaintext = "Server response";
        AesCipherPayload responsePayload = server.encryptWithEcdhHandshakeContext(
                responsePlaintext,
                requestPayload.handshakeContext()
        );

        // 5. Client derives response key using HKDF_INFO_RESPONSE_AES_KEY and response IV
        byte[] responseIv = EncodingUtils.fromBase64(responsePayload.ivBase64());
        SecretKey clientResponseKey = EcdhKeyAgreementService.deriveAesKey(
                clientSharedSecret,
                responseIv,
                CryptoConstants.HKDF_INFO_RESPONSE_AES_KEY
        );

        // Key isolation verification: Request key and Response key MUST be different
        assertFalse(Arrays.equals(clientRequestKey.getEncoded(), clientResponseKey.getEncoded()));

        // Response decrypts successfully with responseKey
        String decryptedResponse = AesGcmCryptoService.decryptFromBase64(
                responsePayload.encryptedDataBase64(),
                clientResponseKey,
                responsePayload.ivBase64()
        );
        assertEquals(responsePlaintext, decryptedResponse);

        // Response decrypting with requestKey MUST fail (GCM authentication tag mismatch)
        assertThrows(GeneralSecurityException.class, () ->
                AesGcmCryptoService.decryptFromBase64(
                        responsePayload.encryptedDataBase64(),
                        clientRequestKey,
                        responsePayload.ivBase64()
                )
        );

        // Verify Redis was queried only ONCE (for request decrypt), never for response encrypt
        Mockito.verify(valueOperations, Mockito.times(1)).get(anyString());
    }
}
