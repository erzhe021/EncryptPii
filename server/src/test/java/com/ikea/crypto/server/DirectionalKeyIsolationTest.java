package com.ikea.crypto.server;

import com.ikea.crypto.common.crypto.KeyAgreementService;
import com.ikea.crypto.common.crypto.KeyPairFactory;
import com.ikea.crypto.common.model.CipherDataPayload;
import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.common.crypto.AesGcmCipher;
import com.ikea.crypto.common.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.model.CipherRequestPayload;
import com.ikea.crypto.common.model.EphemeralKeyResponse;
import com.ikea.crypto.common.model.HandshakeContext;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import com.ikea.crypto.server.service.CryptoServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class DirectionalKeyIsolationTest {

    private CryptoServer server;
    private SecretKey ticketMasterKey;

    @BeforeEach
    void setUp() throws Exception {
        byte[] masterKeyBytes = new byte[CryptoConstants.MASTER_KEY_SIZE_BYTES];
        new SecureRandom().nextBytes(masterKeyBytes);
        ticketMasterKey = new SecretKeySpec(masterKeyBytes, CryptoConstants.ALGORITHM_AES);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyGen.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        KeyPair ecdsaKeyPair = keyGen.generateKeyPair();

        server = new CryptoServer(ecdsaKeyPair.getPrivate(), ecdsaKeyPair.getPublic(), ticketMasterKey);
    }

    @AfterEach
    void tearDown() {
        CryptoSessionContextAccessor.clearCryptoSessionContext();
    }

    @Test
    void testStatelessTicketAndDirectionalKeyIsolation() throws Exception {
        // 1. Server publishes ephemeral public key with stateless ticket
        EphemeralKeyResponse serverEphemeral = server.getEphemeralPublicKey();
        assertNotNull(serverEphemeral.serverKeyTicketBase64());

        // 2. Client negotiates key pair and derives sharedSecret
        KeyPair clientEphemeral = KeyPairFactory.generateEphemeralKeyPair();
        String clientPubBase64 = EncodingUtils.toBase64(clientEphemeral.getPublic().getEncoded());

        byte[] clientSharedSecret = KeyAgreementService.deriveSharedSecret(
                clientEphemeral.getPrivate(),
                KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC)
                        .generatePublic(new X509EncodedKeySpec(EncodingUtils.fromBase64(serverEphemeral.ephemeralPublicKeyBase64())))
        );

        // Client derives client-write-key (request key)
        byte[] requestIv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        SecretKey clientRequestKey = KeyAgreementService.deriveAesKey(
                clientSharedSecret,
                requestIv,
                CryptoConstants.HKDF_INFO_REQUEST_AES_KEY
        );

        String requestPlaintext = "Client payload";
        String encryptedRequestData = AesGcmCipher.encryptAsBase64(requestPlaintext, clientRequestKey, requestIv);

        CipherRequestPayload requestPayload = new CipherRequestPayload(
                new HandshakeContext(clientPubBase64, serverEphemeral.serverKeyTicketBase64()),
                new CipherDataPayload(EncodingUtils.toBase64(requestIv), encryptedRequestData)
        );

        // 3. Server decrypts request statelessly from ticket: calculates sharedSecret, caches in context, decrypts
        String decryptedRequest = server.decrypt(requestPayload);
        assertEquals(requestPlaintext, decryptedRequest);

        // 4. Server encrypts response: reuses sharedSecret from context, derives response key (server-write-key)
        String responsePlaintext = "Server response";
        CipherDataPayload responsePayload = server.encryptWithEcdhHandshakeContext(
                responsePlaintext,
                requestPayload.handshakeContext()
        );

        // 5. Client derives response key using HKDF_INFO_RESPONSE_AES_KEY and response IV
        byte[] responseIv = EncodingUtils.fromBase64(responsePayload.ivBase64());
        SecretKey clientResponseKey = KeyAgreementService.deriveAesKey(
                clientSharedSecret,
                responseIv,
                CryptoConstants.HKDF_INFO_RESPONSE_AES_KEY
        );

        // Key isolation verification: Request key and Response key MUST be different
        assertFalse(Arrays.equals(clientRequestKey.getEncoded(), clientResponseKey.getEncoded()));

        // Response decrypts successfully with responseKey
        String decryptedResponse = AesGcmCipher.decryptFromBase64(
                responsePayload.encryptedDataBase64(),
                clientResponseKey,
                responsePayload.ivBase64()
        );
        assertEquals(responsePlaintext, decryptedResponse);

        // Response decrypting with requestKey MUST fail (GCM authentication tag mismatch)
        assertThrows(GeneralSecurityException.class, () ->
                AesGcmCipher.decryptFromBase64(
                        responsePayload.encryptedDataBase64(),
                        clientRequestKey,
                        responsePayload.ivBase64()
                )
        );
    }

    @Test
    void testTamperedTicketFails() throws Exception {
        EphemeralKeyResponse serverEphemeral = server.getEphemeralPublicKey();
        KeyPair clientEphemeral = KeyPairFactory.generateEphemeralKeyPair();
        String clientPubBase64 = EncodingUtils.toBase64(clientEphemeral.getPublic().getEncoded());

        // Tamper with ticket
        byte[] ticketBytes = EncodingUtils.fromBase64(serverEphemeral.serverKeyTicketBase64());
        ticketBytes[ticketBytes.length - 1] ^= 0xFF;
        String tamperedTicket = EncodingUtils.toBase64(ticketBytes);

        CipherRequestPayload payload = new CipherRequestPayload(
                new HandshakeContext(clientPubBase64, tamperedTicket),
                new CipherDataPayload(EncodingUtils.toBase64(new byte[12]), "encrypted")
        );

        assertThrows(GeneralSecurityException.class, () -> server.decrypt(payload));
    }
}
