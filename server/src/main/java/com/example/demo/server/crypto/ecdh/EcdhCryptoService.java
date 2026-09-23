package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhPublicKeyResponse;
import com.example.demo.crypto.ecdh.HkdfUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

public class EcdhCryptoService {
    private final EcdhCryptoServer cryptoServer;

    public EcdhCryptoService(EcdhCryptoServer cryptoServer) {
        this.cryptoServer = cryptoServer;
    }

    public EcdhPublicKeyResponse getPublicKey() throws GeneralSecurityException {
        return cryptoServer.generateEphemeralEcdhPublicKey();
    }

    public String decrypt(EcdhCipherPayload payload) throws GeneralSecurityException {
        return cryptoServer.decrypt(payload);
    }

    public EcdhCipherPayload encryptWithClientPublicKey(String data, String clientPublicKeyBase64) throws GeneralSecurityException {
        PublicKey clientPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(clientPublicKeyBase64))
        );

        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        keyAgreement.init(cryptoServer.getLongTermIdentityPrivateKey());
        keyAgreement.doPhase(clientPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        new SecureRandom().nextBytes(iv);
        byte[] derivedAesKey = HkdfUtils.deriveAesKey(
                sharedSecret,
                iv,
                CryptoConstants.HKDF_INFO_DATA_AES_KEY.getBytes(StandardCharsets.UTF_8),
                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
        );
        SecretKey aesKey = new SecretKeySpec(derivedAesKey, CryptoConstants.ALGORITHM_AES);

        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
        byte[] encryptedData = aesCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        return new EcdhCipherPayload(
                clientPublicKeyBase64,
                EncodingUtils.toBase64(cryptoServer.getLongTermIdentityPublicKey().getEncoded()),
                EncodingUtils.toBase64(iv),
                EncodingUtils.toBase64(encryptedData)
        );
    }
}
