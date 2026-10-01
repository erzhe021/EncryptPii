package com.ikea.crypto.server;

import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.stc.crypto.KeyAgreementService;
import com.ikea.crypto.stc.crypto.KeyPairFactory;
import com.ikea.crypto.stc.model.CipherDataPayload;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.EphemeralKeyResponse;
import com.ikea.crypto.stc.model.HandshakeContext;
import com.ikea.crypto.stc.model.VerificationKeyResponse;
import com.ikea.crypto.stc.util.EncodingUtils;
import com.ikea.crypto.stc.exception.InvalidCryptoPayloadException;
import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class CryptoServerTest {

    private CryptoServer server;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyGen.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        KeyPair keyPair = keyGen.generateKeyPair();

        KeyGenerator masterKeyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        masterKeyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey masterKey = masterKeyGenerator.generateKey();
        server = new CryptoServer(keyPair.getPrivate(), keyPair.getPublic(), masterKey);
    }

    @AfterEach
    void tearDown() {
        CryptoSessionContextAccessor.clearCryptoSessionContext();
    }

    @Test
    void testGetEcdsaPublicKey() {
        VerificationKeyResponse response = server.getEcdsaPublicKey();
        assertNotNull(response);
        assertNotNull(response.publicKeyBase64());
        assertEquals("ecdsa-20261001", response.keyId());
        assertTrue(response.expiresAtEpochMillis() > System.currentTimeMillis());
    }

    @Test
    void testDecryptValidPayload() throws Exception {
        EphemeralKeyResponse ephemeralResponse = server.getEphemeralPublicKey();
        KeyPair clientKeyPair = KeyPairFactory.generateEphemeralKeyPair();
        byte[] sharedSecret = KeyAgreementService.deriveSharedSecret(
                clientKeyPair.getPrivate(),
                KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC)
                        .generatePublic(new X509EncodedKeySpec(EncodingUtils.fromBase64(ephemeralResponse.ephemeralPublicKeyBase64())))
        );
        byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        SecretKey sessionKey = KeyAgreementService.deriveAesKey(sharedSecret, iv, CryptoConstants.HKDF_INFO_REQUEST_AES_KEY);
        String plaintext = "Secret Message from Client";
        String encryptedData = AesGcmCipher.encryptAsBase64(plaintext, sessionKey, iv);

        CipherRequestPayload payload = new CipherRequestPayload(
                new HandshakeContext(
                        EncodingUtils.toBase64(clientKeyPair.getPublic().getEncoded()),
                        ephemeralResponse.serverKeyTicketBase64()
                ),
                new CipherDataPayload(EncodingUtils.toBase64(iv), encryptedData)
        );

        String decrypted = server.decrypt(payload);
        assertEquals(plaintext, decrypted);
        assertArrayEquals(sharedSecret, CryptoSessionContextAccessor.getSharedSecret());
    }

    @Test
    void testValidatePayloadRejectsMissingFields() {
        assertThrows(IllegalArgumentException.class, () -> server.validatePayload(null));
        assertThrows(IllegalArgumentException.class, () -> server.validatePayload(new CipherRequestPayload(null, null)));
        assertThrows(IllegalArgumentException.class, () -> server.validatePayload(
                new CipherRequestPayload(new HandshakeContext(null, "ticket"), new CipherDataPayload("iv", "data"))
        ));
        assertThrows(IllegalArgumentException.class, () -> server.validatePayload(
                new CipherRequestPayload(new HandshakeContext("pub", null), new CipherDataPayload("iv", "data"))
        ));
    }

    @Test
    void testDecryptFailsWithInvalidTicket() {
        CipherRequestPayload payload = new CipherRequestPayload(
                new HandshakeContext(EncodingUtils.toBase64(new byte[]{1, 2, 3}), EncodingUtils.toBase64(new byte[]{4, 5, 6})),
                new CipherDataPayload(EncodingUtils.toBase64(new byte[12]), EncodingUtils.toBase64(new byte[]{7, 8, 9}))
        );
        assertThrows(IllegalArgumentException.class, () -> server.decrypt(payload));
    }

    @Test
    void testResponseKeyIsDifferentFromRequestKey() throws Exception {
        EphemeralKeyResponse ephemeralResponse = server.getEphemeralPublicKey();
        KeyPair clientKeyPair = KeyPairFactory.generateEphemeralKeyPair();
        byte[] sharedSecret = KeyAgreementService.deriveSharedSecret(
                clientKeyPair.getPrivate(),
                KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC)
                        .generatePublic(new X509EncodedKeySpec(EncodingUtils.fromBase64(ephemeralResponse.ephemeralPublicKeyBase64())))
        );
        byte[] requestIv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        byte[] responseIv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());

        SecretKey requestKey = KeyAgreementService.deriveAesKey(sharedSecret, requestIv, CryptoConstants.HKDF_INFO_REQUEST_AES_KEY);
        SecretKey responseKey = KeyAgreementService.deriveAesKey(sharedSecret, responseIv, CryptoConstants.HKDF_INFO_RESPONSE_AES_KEY);
        assertFalse(Arrays.equals(requestKey.getEncoded(), responseKey.getEncoded()));
    }
}
