package com.ikea.crypto.client;

import com.ikea.crypto.client.ecdh.EcdhCryptoClient;
import com.ikea.crypto.client.ecdh.EcdhHttpClient;
import com.ikea.crypto.common.AesCipherPayload;
import com.ikea.crypto.common.CryptoConstants;
import com.ikea.crypto.common.EncodingUtils;
import com.ikea.crypto.common.core.AesGcmCryptoService;
import com.ikea.crypto.common.core.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.ecdh.EcdhEphemeralKeyResponse;
import com.ikea.crypto.common.ecdh.EcdhKeyAgreementService;
import com.ikea.crypto.common.ecdh.EcdsaVerificationKeyResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class EcdhDirectionalCryptoClientTest {

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
                signatureBase64,
                "mock-key-ticket"
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
    void testBidirectionalKeyIsolation() throws Exception {
        String requestText = "User Request Data";
        EcdhCryptoClient.EncryptionResult result = cryptoClient.encrypt(requestText);

        // Verify sharedSecret is stored in context
        assertNotNull(result.context().sharedSecret());

        // Server derives server-write-key (HKDF_INFO_RESPONSE_AES_KEY) with its new response IV
        byte[] serverResponseIv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        SecretKey serverResponseKey = EcdhKeyAgreementService.deriveAesKey(
                result.context().sharedSecret(),
                serverResponseIv,
                CryptoConstants.HKDF_INFO_RESPONSE_AES_KEY
        );

        // Key isolation verification: Request key != Response key
        assertFalse(Arrays.equals(result.context().sessionKey().getEncoded(), serverResponseKey.getEncoded()));

        String serverResponseText = "Server Response Data";
        String serverEncryptedResponse = AesGcmCryptoService.encryptAsBase64(
                serverResponseText,
                serverResponseKey,
                serverResponseIv
        );

        AesCipherPayload responsePayload = new AesCipherPayload(
                EncodingUtils.toBase64(serverResponseIv),
                serverEncryptedResponse
        );

        // Client decrypts response: derives responseKey using sharedSecret from context
        String decryptedResponse = cryptoClient.decrypt(responsePayload, result.context());
        assertEquals(serverResponseText, decryptedResponse);

        // Trying to decrypt response with request session key MUST fail
        assertThrows(GeneralSecurityException.class, () ->
                AesGcmCryptoService.decryptFromBase64(
                        responsePayload.encryptedDataBase64(),
                        result.context().sessionKey(),
                        responsePayload.ivBase64()
                )
        );
    }
}
