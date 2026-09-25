package com.ikea.crypto.client.ecdh;

import com.ikea.crypto.client.CryptoRequestContext;
import com.ikea.crypto.client.PublicKeyProvider;
import com.ikea.crypto.common.CryptoConstants;
import com.ikea.crypto.common.EncodingUtils;
import com.ikea.crypto.common.core.AesGcmCryptoService;
import com.ikea.crypto.common.ecdh.*;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

/**
 * EcdhCryptoClient is a client-side implementation of the Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol.
 * It provides methods to encrypt and decrypt data using ECDH key exchange and AES-GCM encryption.
 * The class fetches the server's ephemeral public key, verifies its signature, derives a shared secret,
 * and uses it to derive an AES session key for secure communication.
 */
@Slf4j
public class EcdhCryptoClient {
    private final PublicKeyProvider publicKeyProvider;
    private final SecureRandom secureRandom;

    public record EncryptionResult(EcdhCipherPayload payload, CryptoRequestContext context) {
    }

    public record ResponseOnlySession(EcdhResponseOnlyRequest request, CryptoRequestContext context) {
    }

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
    public EncryptionResult encrypt(String data) throws GeneralSecurityException {
        log.info("start to encrypt data using ECDH key exchange and AES-GCM encryption");
        EcdhPublicKeyResponse publicKeyResponse = (EcdhPublicKeyResponse) publicKeyProvider.fetchServerPublicKey();
        verifyServerEphemeralPublicKey(publicKeyResponse);
        NegotiatedKeys negotiatedKeys = negotiateKeys(publicKeyResponse.ephemeralPublicKeyBase64());

        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        log.info("Deriving AES key from sharedSecret and iv with hkdfInfo");
        SecretKey sessionKey = EcdhKeyAgreementService.deriveAesKey(
                negotiatedKeys.sharedSecret(),
                iv,
                CryptoConstants.HKDF_INFO_REQUEST_AES_KEY
        );

        String encryptedDataBase64 = AesGcmCryptoService.encryptAsBase64(data, sessionKey, iv);

        return new EncryptionResult(
                new EcdhCipherPayload(
                        negotiatedKeys.clientEphemeralPublicKeyBase64(),
                        publicKeyResponse.ephemeralPublicKeyBase64(),
                        EncodingUtils.toBase64(iv),
                        encryptedDataBase64
                ),
                new CryptoRequestContext(
                        CryptoConstants.ALGORITHM_ECDH,
                        UUID.randomUUID().toString(),
                        new SecretKeySpec(HkdfUtils.deriveAesKey(
                                negotiatedKeys.sharedSecret(),
                                iv,
                                CryptoConstants.HKDF_INFO_REQUEST_AES_KEY.getBytes(StandardCharsets.UTF_8),
                                CryptoConstants.AES_KEY_SIZE_BITS / Byte.SIZE
                        ), CryptoConstants.ALGORITHM_AES),
                        iv,
                        negotiatedKeys.clientEphemeralPrivateKey(),
                        negotiatedKeys.serverEphemeralPublicKey()
                )
        );
    }

    /**
     * Creates a response-only session for ECDH encryption.
     * This method fetches the server's ephemeral public key, verifies its signature, and derives a shared secret.
     * It returns a ResponseOnlySession containing the request payload and the context needed for response decryption.
     *
     * @param data The plaintext data to send in the request. Can be null if no data is being sent.
     * @return A ResponseOnlySession containing the request payload and context for response decryption.
     * @throws GeneralSecurityException If key negotiation or signature verification fails due to cryptographic errors.
     */
    public ResponseOnlySession createResponseOnlySession(String data) throws GeneralSecurityException {
        log.info("start to create response only session");
        EcdhPublicKeyResponse publicKeyResponse = (EcdhPublicKeyResponse) publicKeyProvider.fetchServerPublicKey();
        verifyServerEphemeralPublicKey(publicKeyResponse);
        NegotiatedKeys negotiatedKeys = negotiateKeys(publicKeyResponse.ephemeralPublicKeyBase64());
        return new ResponseOnlySession(
                new EcdhResponseOnlyRequest(
                        data,
                        negotiatedKeys.clientEphemeralPublicKeyBase64(),
                        publicKeyResponse.ephemeralPublicKeyBase64()
                ),
                new CryptoRequestContext(
                        CryptoConstants.ALGORITHM_ECDH,
                        UUID.randomUUID().toString(),
                        null, // No session key is derived for response-only requests, as the server will derive its own session key for the response
                        null, // No IV is generated for response-only requests, as the server will generate its own IV for the response
                        negotiatedKeys.clientEphemeralPrivateKey(),
                        negotiatedKeys.serverEphemeralPublicKey()
                )
        );
    }

    /**
     * Decrypts the given EcdhCipherPayload using the response AES key derived from the shared secret.
     *
     * @param payload The EcdhCipherPayload containing the encrypted data and associated metadata.
     * @return The decrypted plaintext data as a String.
     * @throws GeneralSecurityException If decryption fails due to cryptographic errors or missing keys.
     */
    public String decrypt(EcdhCipherPayload payload, CryptoRequestContext context) throws GeneralSecurityException {
        log.info("start to decrypt payload using context");
        if (payload == null) {
            throw new IllegalArgumentException("payload cannot be null");
        }
        if (context == null || context.clientEphemeralPrivateKey() == null || context.serverEphemeralPublicKey() == null) {
            throw new IllegalStateException("No ECDH key agreement state available for response decryption");
        }

        log.info("Deriving AES key from context.clientEphemeralPrivateKey, context.serverEphemeralPublicKey, iv and hkdfInfo");
        SecretKey responseKey = EcdhKeyAgreementService.deriveAesKey(
                context.clientEphemeralPrivateKey(),
                context.serverEphemeralPublicKey(),
                EncodingUtils.fromBase64(payload.ivBase64()),
                CryptoConstants.HKDF_INFO_RESPONSE_AES_KEY);

        return AesGcmCryptoService.decryptFromBase64(
                payload.encryptedDataBase64(),
                responseKey,
                payload.ivBase64()
        );
    }

    /**
     * Performs ECDH key negotiation with the server's ephemeral public key.
     * Generates a client ephemeral key pair, derives a shared secret, and returns the negotiated keys.
     *
     * @param serverEphemeralPublicKeyBase64 The server's ephemeral public key in Base64 encoding.
     * @return A NegotiatedKeys object containing the shared secret and the client's ephemeral public key in Base64.
     * @throws GeneralSecurityException If key negotiation fails due to cryptographic errors.
     */
    private NegotiatedKeys negotiateKeys(String serverEphemeralPublicKeyBase64) throws GeneralSecurityException {
        log.info("Start to negotiate ECDH keys with server ephemeral public key");
        // Decode the server's ephemeral public key from Base64 and create a PublicKey object
        PublicKey serverPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(serverEphemeralPublicKeyBase64))
        );

        // Generate a new ephemeral key pair for the client using the same curve as the server
        KeyPair ephemeralKeyPair = EcdhKeyPairFactory.generateEphemeralKeyPair(secureRandom);

        // Convert the client's ephemeral public key to Base64 for transmission
        String clientEphemeralPublicKeyBase64 = EncodingUtils.toBase64(ephemeralKeyPair.getPublic().getEncoded());

        // Perform ECDH key agreement to derive the shared secret using the client's private key and the server's public key
        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        // Initialize the key agreement with the client's ephemeral private key
        keyAgreement.init(ephemeralKeyPair.getPrivate());
        // Complete the key agreement phase with the server's public key
        keyAgreement.doPhase(serverPublicKey, true);
        // Generate the shared secret from the key agreement
        byte[] sharedSecret = keyAgreement.generateSecret();

        // Return the negotiated keys containing the shared secret and the client's ephemeral public key in Base64
        return new NegotiatedKeys(
                sharedSecret,
                clientEphemeralPublicKeyBase64,
                ephemeralKeyPair.getPrivate(),
                serverPublicKey
        );
    }

    /**
     * A record to hold the negotiated keys, including the shared secret and the client's ephemeral public key in Base64.
     *
     * @param sharedSecret The shared secret derived from ECDH key agreement.
     * @param clientEphemeralPublicKeyBase64 The client's ephemeral public key in Base64 encoding.
     * @param clientEphemeralPrivateKey The client's ephemeral private key used for later response decryption.
     * @param serverEphemeralPublicKey The server's ephemeral public key used for later response decryption.
     */
    private record NegotiatedKeys(byte[] sharedSecret,
                                  String clientEphemeralPublicKeyBase64,
                                  PrivateKey clientEphemeralPrivateKey,
                                  PublicKey serverEphemeralPublicKey) {
    }

    /**
     * Verifies the server's ephemeral public key signature using the provided EcdhPublicKeyResponse.
     * Throws a GeneralSecurityException if the signature verification fails or if required fields are missing.
     *
     * @param response The EcdhPublicKeyResponse containing the server's ephemeral public key and signature.
     * @throws GeneralSecurityException If signature verification fails or required fields are missing.
     */
    private void verifyServerEphemeralPublicKey(EcdhPublicKeyResponse response) throws GeneralSecurityException {
        log.info("start to verify server ephemeral public key signature using ECDSA public key");
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

}
