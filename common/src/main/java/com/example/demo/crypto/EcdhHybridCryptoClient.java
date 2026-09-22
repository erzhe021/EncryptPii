package com.example.demo.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

public class EcdhHybridCryptoClient {
    private final PublicKeyProvider publicKeyProvider;
    private final SecureRandom secureRandom;

    public EcdhHybridCryptoClient(PublicKeyProvider publicKeyProvider) {
        this.publicKeyProvider = publicKeyProvider;
        this.secureRandom = new SecureRandom();
    }

    public EcdhHybridCipherPayload encrypt(String data) throws GeneralSecurityException {
        EcdhPublicKeyResponse publicKeyResponse = (EcdhPublicKeyResponse) publicKeyProvider.fetchServerPublicKey();
        verifyServerEphemeralPublicKey(publicKeyResponse);
        PublicKey serverPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(publicKeyResponse.ephemeralPublicKeyBase64()))
        );

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyPairGenerator.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH), secureRandom);
        KeyPair ephemeralKeyPair = keyPairGenerator.generateKeyPair();
        String clientEphemeralPublicKeyBase64 = EncodingUtils.toBase64(ephemeralKeyPair.getPublic().getEncoded());

        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        keyAgreement.init(ephemeralKeyPair.getPrivate());
        keyAgreement.doPhase(serverPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        byte[] derivedAesKey = HkdfUtils.deriveAesKey(
                sharedSecret,
                iv,
                CryptoConstants.HKDF_INFO_DATA_AES_KEY.getBytes(StandardCharsets.UTF_8),
                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
        );
        SecretKey aesKey = new SecretKeySpec(derivedAesKey, CryptoConstants.ALGORITHM_AES);

        byte[] encryptedData = encryptWithAes(data, aesKey, iv);

        return new EcdhHybridCipherPayload(
                CryptoConstants.ALGORITHM_ECDH_HKDF_AES,
                clientEphemeralPublicKeyBase64,
                publicKeyResponse.ephemeralPublicKeyBase64(),
                EncodingUtils.toBase64(iv),
                EncodingUtils.toBase64(encryptedData)
        );
    }

    private void verifyServerEphemeralPublicKey(EcdhPublicKeyResponse response) throws GeneralSecurityException {
        if (response == null) {
            throw new GeneralSecurityException("ECDH public key response is missing");
        }
        if (response.identityPublicKeyBase64() == null || response.identityPublicKeyBase64().isBlank()) {
            throw new GeneralSecurityException("Server identity public key is required for ECDH signature verification");
        }
        if (response.signatureBase64() == null || response.signatureBase64().isBlank()) {
            throw new GeneralSecurityException("Server ECDH signature is missing");
        }

        PublicKey identityPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(response.identityPublicKeyBase64()))
        );
        Signature signature = Signature.getInstance(CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA);
        signature.initVerify(identityPublicKey);
        signature.update(EncodingUtils.fromBase64(response.ephemeralPublicKeyBase64()));
        boolean verified = signature.verify(EncodingUtils.fromBase64(response.signatureBase64()));
        if (!verified) {
            throw new GeneralSecurityException("Server ECDH ephemeral public key signature verification failed");
        }
    }

    private byte[] encryptWithAes(String data, SecretKey aesKey, byte[] iv) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
        return aesCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

}
