package com.ikea.crypto.client;

import com.ikea.crypto.client.context.CryptoRequestContext;
import com.ikea.crypto.client.core.CryptoClient;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.stc.crypto.SessionKeyService;
import com.ikea.crypto.stc.model.CipherResponsePayload;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.util.EncodingUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class CryptoClientTest {

    private CryptoClient cryptoClient;
    private KeyPair serverKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        cryptoClient = new CryptoClient();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        keyGen.initialize(CryptoConstants.RSA_KEY_SIZE_BITS);
        serverKeyPair = keyGen.generateKeyPair();
    }

    @Test
    void testEncryptAndDecrypt() throws Exception {
        String originalData = "Hello RSA Encrypted World";

        CryptoClient.EncryptionResult result = cryptoClient.encrypt(originalData, serverKeyPair.getPublic());

        CipherRequestPayload payload = result.payload();
        assertNotNull(payload);
        assertNotNull(payload.encryptedSessionKeyBase64());
        assertNotNull(payload.ivBase64());
        assertNotNull(payload.encryptedDataBase64());

        CryptoRequestContext context = result.context();
        assertNotNull(context);
        assertNotNull(context.requestId());
        assertNotNull(context.sessionKey());
        assertNotNull(context.iv());

        // Server decrypts session key using server RSA private key
        SecretKey recoveredSessionKey = SessionKeyService.decryptSessionKeyBase64(
                payload.encryptedSessionKeyBase64(),
                serverKeyPair.getPrivate()
        );
        assertArrayEquals(context.sessionKey().getEncoded(), recoveredSessionKey.getEncoded());

        // Server decrypts AES data
        String decryptedByServer = AesGcmCipher.decryptFromBase64(
                payload.encryptedDataBase64(),
                recoveredSessionKey,
                payload.ivBase64()
        );
        assertEquals(originalData, decryptedByServer);

        // Server encrypts a response using the same session key
        String serverResponse = "Response Data from Server";
        byte[] responseIv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        String encryptedResponseData = AesGcmCipher.encryptAsBase64(serverResponse, recoveredSessionKey, responseIv);
        CipherResponsePayload responsePayload = new CipherResponsePayload(EncodingUtils.toBase64(responseIv), encryptedResponseData);

        // Client decrypts response using context
        String decryptedByClient = cryptoClient.decrypt(responsePayload, context);
        assertEquals(serverResponse, decryptedByClient);

        // Client decrypts response using direct session key
        String decryptedWithKey = cryptoClient.decrypt(responsePayload, context.sessionKey());
        assertEquals(serverResponse, decryptedWithKey);
    }

    @Test
    void testDecryptFailsWithTamperedData() throws Exception {
        String originalData = "Sensitive Data";
        CryptoClient.EncryptionResult result = cryptoClient.encrypt(originalData, serverKeyPair.getPublic());

        byte[] responseIv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());
        String encryptedResponse = AesGcmCipher.encryptAsBase64("Response", result.context().sessionKey(), responseIv);
        CipherResponsePayload tamperedPayload = new CipherResponsePayload(
                EncodingUtils.toBase64(responseIv),
                encryptedResponse + "corrupt"
        );

        assertThrows(GeneralSecurityException.class, () ->
                cryptoClient.decrypt(tamperedPayload, result.context())
        );
    }
}
