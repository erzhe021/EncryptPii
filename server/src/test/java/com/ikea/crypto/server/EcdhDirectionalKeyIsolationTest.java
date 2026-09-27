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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class EcdhDirectionalKeyIsolationTest {

    private EcdhCryptoServer server;
    private SecretKey ticketMasterKey;

    @BeforeEach
    void setUp() throws Exception {
        byte[] masterKeyBytes = new byte[CryptoConstants.MASTER_KEY_SIZE_BYTES];
        new SecureRandom().nextBytes(masterKeyBytes);
        ticketMasterKey = new SecretKeySpec(masterKeyBytes, CryptoConstants.ALGORITHM_AES);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyGen.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        KeyPair ecdsaKeyPair = keyGen.generateKeyPair();

        server = new EcdhCryptoServer(ecdsaKeyPair.getPrivate(), ecdsaKeyPair.getPublic(), ticketMasterKey);
    }

    @AfterEach
    void tearDown() {
        CryptoSessionContextAccessor.clearCryptoSessionContext();
    }

    @Test
    void testStatelessTicketAndDirectionalKeyIsolation() throws Exception {
        // 1. Server publishes ephemeral public key with stateless ticket
        EcdhEphemeralKeyResponse serverEphemeral = server.getEphemeralPublicKey();
        assertNotNull(serverEphemeral.serverKeyTicketBase64());

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
                new EcdhHandshakeContext(clientPubBase64, serverEphemeral.serverKeyTicketBase64()),
                new AesCipherPayload(EncodingUtils.toBase64(requestIv), encryptedRequestData)
        );

        // 3. Server decrypts request statelessly from ticket: calculates sharedSecret, caches in context, decrypts
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
    }

    @Test
    void testTamperedTicketFails() throws Exception {
        EcdhEphemeralKeyResponse serverEphemeral = server.getEphemeralPublicKey();
        KeyPair clientEphemeral = EcdhKeyPairFactory.generateEphemeralKeyPair();
        String clientPubBase64 = EncodingUtils.toBase64(clientEphemeral.getPublic().getEncoded());

        // Tamper with ticket
        byte[] ticketBytes = EncodingUtils.fromBase64(serverEphemeral.serverKeyTicketBase64());
        ticketBytes[ticketBytes.length - 1] ^= 0xFF;
        String tamperedTicket = EncodingUtils.toBase64(ticketBytes);

        EcdhCipherPayload payload = new EcdhCipherPayload(
                new EcdhHandshakeContext(clientPubBase64, tamperedTicket),
                new AesCipherPayload(EncodingUtils.toBase64(new byte[12]), "encrypted")
        );

        assertThrows(GeneralSecurityException.class, () -> server.decrypt(payload));
    }
}
