package com.example.demo.crypto.ecdh;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.PublicKeyProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EcdhCryptoClientTest {

    @Test
    void decryptsServerResponseWithSameSharedSecretButNewIv() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyPairGenerator.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        KeyPair identityKeyPair = keyPairGenerator.generateKeyPair();
        KeyPair serverEphemeralKeyPair = keyPairGenerator.generateKeyPair();
        byte[] serverPublicKeyBytes = serverEphemeralKeyPair.getPublic().getEncoded();
        String serverPublicKeyBase64 = EncodingUtils.toBase64(serverPublicKeyBytes);

        Signature signature = Signature.getInstance(CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA);
        signature.initSign(identityKeyPair.getPrivate());
        signature.update(serverPublicKeyBytes);

        EcdhPublicKeyResponse publicKeyResponse = new EcdhPublicKeyResponse(
                CryptoConstants.ALGORITHM_ECDH,
                CryptoConstants.CURVE_ECDH,
                serverPublicKeyBase64,
                EncodingUtils.toBase64(identityKeyPair.getPublic().getEncoded()),
                CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA,
                EncodingUtils.toBase64(signature.sign())
        );

        PublicKeyProvider provider = () -> publicKeyResponse;
        EcdhCryptoClient client = new EcdhCryptoClient(provider);

        String requestPlainText = "{\"data\":\"hello\"}";
        EcdhCipherPayload encryptedRequest = client.encrypt(requestPlainText);

        PublicKey clientPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(encryptedRequest.clientEphemeralPublicKeyBase64()))
        );
        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        keyAgreement.init(serverEphemeralKeyPair.getPrivate());
        keyAgreement.doPhase(clientPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        byte[] responseIv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(responseIv);
        SecretKey responseKey = new SecretKeySpec(
                HkdfUtils.deriveAesKey(
                        sharedSecret,
                        responseIv,
                        CryptoConstants.HKDF_INFO_DATA_AES_KEY.getBytes(StandardCharsets.UTF_8),
                        CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
                ),
                CryptoConstants.ALGORITHM_AES
        );
        Cipher cipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        cipher.init(Cipher.ENCRYPT_MODE, responseKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, responseIv));
        String responsePlainText = "{\"data\":\"mock ecdh response for request - hello\"}";
        byte[] encryptedResponsePayload = cipher.doFinal(responsePlainText.getBytes(StandardCharsets.UTF_8));

        EcdhCipherPayload encryptedResponse = new EcdhCipherPayload(
                encryptedRequest.clientEphemeralPublicKeyBase64(),
                encryptedRequest.serverEphemeralPublicKeyBase64(),
                EncodingUtils.toBase64(responseIv),
                EncodingUtils.toBase64(encryptedResponsePayload)
        );

        assertEquals(responsePlainText, client.decrypt(encryptedResponse));
    }
}
