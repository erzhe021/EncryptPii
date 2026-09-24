package com.example.demo.crypto.ecdh;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.PublicKeyProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * EcdhCryptoClient is a client-side implementation of the Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol.
 * It provides methods to encrypt and decrypt data using ECDH key exchange and AES-GCM encryption.
 * The class fetches the server's ephemeral public key, verifies its signature, derives a shared secret,
 * and uses it to derive an AES session key for secure communication.
 */
public class EcdhCryptoClient {
    private final PublicKeyProvider publicKeyProvider;
    private final SecureRandom secureRandom;
    private PrivateKey clientEphemeralPrivateKey;
    private PublicKey serverEphemeralPublicKey;

    public EcdhCryptoClient(PublicKeyProvider publicKeyProvider) {
        this.publicKeyProvider = publicKeyProvider;
        this.secureRandom = new SecureRandom();
    }

    /**
     * Encrypts the given data using ECDH key exchange and AES-GCM encryption.
     * The method fetches the server's ephemeral public key, verifies its signature, and derives a shared secret.
     * A request AES key is derived from the shared secret and used to encrypt the data.
     *
     * @param data The plaintext data to encrypt.
     * @return An EcdhCipherPayload containing the client's ephemeral public key, server's ephemeral public key,
     *         IV, and encrypted data.
     * @throws GeneralSecurityException If encryption fails due to cryptographic errors or signature verification failure.
     */
    public EcdhCipherPayload encrypt(String data) throws GeneralSecurityException {
        EcdhPublicKeyResponse publicKeyResponse = (EcdhPublicKeyResponse) publicKeyProvider.fetchServerPublicKey();
        verifyServerEphemeralPublicKey(publicKeyResponse);
        NegotiatedKeys negotiatedKeys = negotiateKeys(publicKeyResponse.ephemeralPublicKeyBase64());

        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        byte[] derivedAesKey = HkdfUtils.deriveAesKey(
                negotiatedKeys.sharedSecret(),
                iv,
                CryptoConstants.HKDF_INFO_REQUEST_AES_KEY.getBytes(StandardCharsets.UTF_8),
                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
        );
        SecretKey requestKey = new SecretKeySpec(derivedAesKey, CryptoConstants.ALGORITHM_AES);

        byte[] encryptedData = encryptWithAes(data, requestKey, iv);

        return new EcdhCipherPayload(
                negotiatedKeys.clientEphemeralPublicKeyBase64(),
                publicKeyResponse.ephemeralPublicKeyBase64(),
                EncodingUtils.toBase64(iv),
                EncodingUtils.toBase64(encryptedData)
        );
    }

    public EcdhResponseOnlyRequest createResponseOnlyRequest(String data) throws GeneralSecurityException {
        EcdhPublicKeyResponse publicKeyResponse = (EcdhPublicKeyResponse) publicKeyProvider.fetchServerPublicKey();
        verifyServerEphemeralPublicKey(publicKeyResponse);
        NegotiatedKeys negotiatedKeys = negotiateKeys(publicKeyResponse.ephemeralPublicKeyBase64());
        return new EcdhResponseOnlyRequest(
                data,
                negotiatedKeys.clientEphemeralPublicKeyBase64(),
                publicKeyResponse.ephemeralPublicKeyBase64()
        );
    }

    /**
     * Decrypts the given EcdhCipherPayload using the response AES key derived from the shared secret.
     *
     * @param payload The EcdhCipherPayload containing the encrypted data and associated metadata.
     * @return The decrypted plaintext data as a String.
     * @throws GeneralSecurityException If decryption fails due to cryptographic errors or missing keys.
     */
    public String decrypt(EcdhCipherPayload payload) throws GeneralSecurityException {
        if (payload == null) {
            throw new IllegalArgumentException("payload cannot be null");
        }
        if (clientEphemeralPrivateKey == null || serverEphemeralPublicKey == null) {
            throw new IllegalStateException("No ECDH key agreement state available for response decryption");
        }
        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        keyAgreement.init(clientEphemeralPrivateKey);
        keyAgreement.doPhase(serverEphemeralPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        byte[] iv = EncodingUtils.fromBase64(payload.ivBase64());
        byte[] derivedAesKey = HkdfUtils.deriveAesKey(
                sharedSecret,
                iv,
                CryptoConstants.HKDF_INFO_RESPONSE_AES_KEY.getBytes(StandardCharsets.UTF_8),
                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
        );
        SecretKey responseKey = new SecretKeySpec(derivedAesKey, CryptoConstants.ALGORITHM_AES);

        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(
                Cipher.DECRYPT_MODE,
                responseKey,
                new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, EncodingUtils.fromBase64(payload.ivBase64()))
        );
        byte[] plainBytes = aesCipher.doFinal(EncodingUtils.fromBase64(payload.encryptedDataBase64()));
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    private NegotiatedKeys negotiateKeys(String serverEphemeralPublicKeyBase64) throws GeneralSecurityException {
        PublicKey serverPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(serverEphemeralPublicKeyBase64))
        );

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        keyPairGenerator.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH), secureRandom);
        KeyPair ephemeralKeyPair = keyPairGenerator.generateKeyPair();
        String clientEphemeralPublicKeyBase64 = EncodingUtils.toBase64(ephemeralKeyPair.getPublic().getEncoded());

        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        keyAgreement.init(ephemeralKeyPair.getPrivate());
        keyAgreement.doPhase(serverPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        this.clientEphemeralPrivateKey = ephemeralKeyPair.getPrivate();
        this.serverEphemeralPublicKey = serverPublicKey;
        return new NegotiatedKeys(sharedSecret, clientEphemeralPublicKeyBase64);
    }

    private record NegotiatedKeys(byte[] sharedSecret, String clientEphemeralPublicKeyBase64) {
    }

    /**
     * Verifies the server's ephemeral public key signature using the provided EcdhPublicKeyResponse.
     * Throws a GeneralSecurityException if the signature verification fails or if required fields are missing.
     *
     * @param response The EcdhPublicKeyResponse containing the server's ephemeral public key and signature.
     * @throws GeneralSecurityException If signature verification fails or required fields are missing.
     */
    private void verifyServerEphemeralPublicKey(EcdhPublicKeyResponse response) throws GeneralSecurityException {
        if (response == null) {
            throw new GeneralSecurityException("ECDH public key response is missing");
        }
        if (response.ecdsaPublicKeyBase64() == null || response.ecdsaPublicKeyBase64().isBlank()) {
            throw new GeneralSecurityException("Server ECDSA public key is required for ECDH signature verification");
        }
        if (response.signatureBase64() == null || response.signatureBase64().isBlank()) {
            throw new GeneralSecurityException("Server ECDH signature is missing");
        }

        PublicKey ecdsaPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(response.ecdsaPublicKeyBase64()))
        );
        Signature signature = Signature.getInstance(response.signatureAlgorithm());
        signature.initVerify(ecdsaPublicKey);
        signature.update(EncodingUtils.fromBase64(response.ephemeralPublicKeyBase64()));
        boolean verified = signature.verify(EncodingUtils.fromBase64(response.signatureBase64()));
        if (!verified) {
            throw new GeneralSecurityException("Server ECDH ephemeral public key signature verification failed");
        }
    }

    /**
     * Encrypts the given data using AES-GCM encryption with the provided AES key and initialization vector (IV).
     *
     * @param data   The plaintext data to encrypt.
     * @param aesKey The AES session key for encryption.
     * @param iv     The initialization vector (IV) for AES-GCM.
     * @return The encrypted data as a byte array.
     * @throws GeneralSecurityException If encryption fails due to cryptographic errors.
     */
    private byte[] encryptWithAes(String data, SecretKey aesKey, byte[] iv) throws GeneralSecurityException {
        Cipher aesCipher = Cipher.getInstance(CryptoConstants.TRANSFORMATION_AES);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(CryptoConstants.GCM_TAG_LENGTH_BITS, iv));
        return aesCipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }

}
