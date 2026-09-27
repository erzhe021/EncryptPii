package com.ikea.crypto.client;

import com.ikea.crypto.client.ecdh.EcdhCryptoClient;
import com.ikea.crypto.client.ecdh.EcdhHttpClient;
import com.ikea.crypto.common.AesCipherPayload;
import com.ikea.crypto.common.CryptoConstants;
import com.ikea.crypto.common.EncodingUtils;
import com.ikea.crypto.common.core.AesGcmCryptoService;
import com.ikea.crypto.common.core.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.ecdh.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.Mockito.when;

class EcdhClientCryptoTest {

    private EcdhHttpClient ecdhHttpClient;
    private EcdhCryptoClient cryptoClient;
    private KeyPair ecdsaKeyPair;
    private KeyPair serverEphemeralKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        ecdhHttpClient = Mockito.mock(EcdhHttpClient.class);
        cryptoClient = new EcdhCryptoClient(ecdhHttpClient);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyGen.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        ecdsaKeyPair = keyGen.generateKeyPair();
        serverEphemeralKeyPair = keyGen.generateKeyPair();

        // Sign server ephemeral key with ECDSA private key
        Signature signature = Signature.getInstance(CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA);
        signature.initSign(ecdsaKeyPair.getPrivate());
        signature.update(serverEphemeralKeyPair.getPublic().getEncoded());
        String signatureBase64 = EncodingUtils.toBase64(signature.sign());

        EcdhEphemeralKeyResponse ephemeralResponse = new EcdhEphemeralKeyResponse(
                EncodingUtils.toBase64(serverEphemeralKeyPair.getPublic().getEncoded()),
                CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA,
                signatureBase64
        );
        EcdsaVerificationKeyResponse verificationKeyResponse = new EcdsaVerificationKeyResponse(
                EncodingUtils.toBase64(ecdsaKeyPair.getPublic().getEncoded()),
                "ecdsa-test",
                System.currentTimeMillis() + 60000
        );

        when(ecdhHttpClient.fetchEphemeralPublicKey()).thenReturn(ephemeralResponse);
        when(ecdhHttpClient.fetchEcdsaPublicKey()).thenReturn(verificationKeyResponse);
    }

    @Test
    void testBidirectionalDecryptReusesSessionKey() throws Exception {
        String requestText = "User Request Data";
        EcdhCryptoClient.EncryptionResult result = cryptoClient.encrypt(requestText);

        // Server simulates response using SAME session key and a NEW IV
        byte[] serverResponseIv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        String serverResponseText = "Server Response Data";
        String serverEncryptedResponse = AesGcmCryptoService.encryptAsBase64(
                serverResponseText,
                result.context().sessionKey(),
                serverResponseIv
        );

        EcdhCipherPayload serverResponsePayload = new EcdhCipherPayload(
                result.payload().handshakeContext(),
                new AesCipherPayload(EncodingUtils.toBase64(serverResponseIv), serverEncryptedResponse)
        );

        // Client decrypts response with the existing context
        String decryptedResponse = cryptoClient.decrypt(serverResponsePayload, result.context());
        assertEquals(serverResponseText, decryptedResponse);
        assertNotEquals(result.payload().aesCipherPayload().ivBase64(), serverResponsePayload.aesCipherPayload().ivBase64());
    }
}
