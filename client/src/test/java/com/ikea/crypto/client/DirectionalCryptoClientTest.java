package com.ikea.crypto.client;

import com.ikea.crypto.client.core.CryptoClient;
import com.ikea.crypto.client.model.DemoPlainRequest;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.stc.crypto.KeyAgreementService;
import com.ikea.crypto.stc.model.CipherDataPayload;
import com.ikea.crypto.stc.model.EphemeralKeyResponse;
import com.ikea.crypto.stc.model.VerificationKeyResponse;
import com.ikea.crypto.stc.util.EncodingUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class DirectionalCryptoClientTest {

    private CryptoClient cryptoClient;
    private KeyPair ecdsaKeyPair;
    private KeyPair serverEphemeralKeyPair;
    private EphemeralKeyResponse ephemeralResponse;
    private VerificationKeyResponse verificationKeyResponse;

    @BeforeEach
    void setUp() throws Exception {
        cryptoClient = new CryptoClient();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyGen.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        ecdsaKeyPair = keyGen.generateKeyPair();
        serverEphemeralKeyPair = keyGen.generateKeyPair();

        // Sign server ephemeral key with ECDSA private key
        Signature signature = Signature.getInstance(CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA);
        signature.initSign(ecdsaKeyPair.getPrivate());
        signature.update(serverEphemeralKeyPair.getPublic().getEncoded());
        String signatureBase64 = EncodingUtils.toBase64(signature.sign());

        ephemeralResponse = new EphemeralKeyResponse(
                EncodingUtils.toBase64(serverEphemeralKeyPair.getPublic().getEncoded()),
                CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA,
                signatureBase64,
                "mock-key-ticket"
        );
        verificationKeyResponse = new VerificationKeyResponse(
                EncodingUtils.toBase64(ecdsaKeyPair.getPublic().getEncoded()),
                "ecdsa-test",
                System.currentTimeMillis() + 60000
        );
    }

    @Test
    void testBidirectionalKeyIsolation() throws Exception {
        String requestText = "User Request Data";
        CryptoClient.EncryptionResult result = cryptoClient.encrypt(requestText, ephemeralResponse, verificationKeyResponse);

        // Verify sharedSecret is stored in context
        assertNotNull(result.context().sharedSecret());

        // Server derives server-write-key (HKDF_INFO_RESPONSE_AES_KEY) with its new response IV
        byte[] serverResponseIv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        SecretKey serverResponseKey = KeyAgreementService.deriveAesKey(
                result.context().sharedSecret(),
                serverResponseIv,
                CryptoConstants.HKDF_INFO_RESPONSE_AES_KEY
        );

        // Key isolation verification: Request key != Response key
        assertFalse(Arrays.equals(result.context().sessionKey().getEncoded(), serverResponseKey.getEncoded()));

        String serverResponseText = "Server Response Data";
        String serverEncryptedResponse = AesGcmCipher.encryptAsBase64(
                serverResponseText,
                serverResponseKey,
                serverResponseIv
        );

        CipherDataPayload responsePayload = new CipherDataPayload(
                EncodingUtils.toBase64(serverResponseIv),
                serverEncryptedResponse
        );

        // Client decrypts response: derives responseKey using sharedSecret from context
        String decryptedResponse = cryptoClient.decrypt(responsePayload, result.context());
        assertEquals(serverResponseText, decryptedResponse);

        // Trying to decrypt response with request session key MUST fail
        assertThrows(GeneralSecurityException.class, () ->
                AesGcmCipher.decryptFromBase64(
                        responsePayload.encryptedDataBase64(),
                        result.context().sessionKey(),
                        responsePayload.ivBase64()
                )
        );
    }

    @Test
    void testResponseOnlySession() throws Exception {
//        String requestText = "User Request Plain Text";
//        DemoPlainRequest request = new DemoPlainRequest(requestText);
//        CryptoClient.ResponseOnlySession result = cryptoClient.createResponseOnlySession(
//                request, ephemeralResponse, verificationKeyResponse
//        );
//
//        assertNotNull(result.context().sharedSecret());
//        assertEquals(requestText, result.request().request());
//        assertEquals("mock-key-ticket", result.request().handshakeContext().serverKeyTicketBase64());
//        assertNotNull(result.request().handshakeContext().clientEphemeralPublicKeyBase64());
    }

    @Test
    void testInvalidSignatureThrowsException() {
        EphemeralKeyResponse invalidSignatureResponse = new EphemeralKeyResponse(
                ephemeralResponse.ephemeralPublicKeyBase64(),
                ephemeralResponse.signatureAlgorithm(),
                EncodingUtils.toBase64("invalid-signature".getBytes()),
                ephemeralResponse.serverKeyTicketBase64()
        );

        assertThrows(GeneralSecurityException.class, () ->
                cryptoClient.encrypt("test", invalidSignatureResponse, verificationKeyResponse)
        );
    }
}
