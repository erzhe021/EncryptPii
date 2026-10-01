package com.ikea.crypto.client.core;

import com.ikea.crypto.client.model.CryptoRequestContext;
import com.ikea.crypto.client.model.DemoPlainRequest;
import com.ikea.crypto.client.model.PlainRequestPayload;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.stc.crypto.KeyAgreementService;
import com.ikea.crypto.stc.crypto.KeyPairFactory;
import com.ikea.crypto.stc.model.*;
import com.ikea.crypto.stc.util.EncodingUtils;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

/**
 * CryptoClient is a client-side implementation of the Elliptic Curve Diffie-Hellman (ECDH) key exchange protocol.
 * It provides methods to encrypt and decrypt request using ECDH key exchange and AES-GCM encryption.
 * It is solely responsible for cryptographic operations (ECDSA signature verification, ECDH key agreement,
 * HKDF key derivation, and AES-GCM encryption/decryption) without any network or HTTP transport dependencies.
 */
@Slf4j
public class CryptoClient {
    private final SecureRandom secureRandom;

    public record EncryptionResult(CipherRequestPayload payload, CryptoRequestContext context) {
    }

    public record ResponseOnlySession(PlainRequestPayload request, CryptoRequestContext context) {
    }

    public CryptoClient() {
        this(new SecureRandom());
    }

    public CryptoClient(SecureRandom secureRandom) {
        this.secureRandom = secureRandom;
    }

    /**
     * Encrypts the given request using ECDH key exchange and AES-GCM encryption.
     * The method verifies the server's ephemeral public key signature, derives a shared secret,
     * and derives a request AES key to encrypt the request.
     *
     * @param data The plaintext request to encrypt.
     * @param ephemeralResponse The server's ephemeral public key response.
     * @param ecdsaResponse The server's ECDSA verification key response.
     * @return An EncryptionResult containing the cipher request payload and crypto context for response decryption.
     * @throws GeneralSecurityException If encryption fails due to cryptographic errors or signature verification failure.
     */
    public EncryptionResult encrypt(
            String data,
            EphemeralKeyResponse ephemeralResponse,
            VerificationKeyResponse ecdsaResponse
    ) throws GeneralSecurityException {
        log.debug("start to encrypt request using ECDH key exchange and AES-GCM encryption");
        verifyServerEphemeralPublicKey(ephemeralResponse, ecdsaResponse);
        NegotiatedKeys negotiatedKeys = negotiateKeys(ephemeralResponse.ephemeralPublicKeyBase64());

        byte[] iv = CryptoSessionMaterialFactory.generateIv(secureRandom);
        log.debug("Deriving request AES key from sharedSecret, iv and hkdfInfo");
        SecretKey sessionKey = KeyAgreementService.deriveAesKey(
                negotiatedKeys.sharedSecret(),
                iv,
                CryptoConstants.HKDF_INFO_REQUEST_AES_KEY
        );

        String encryptedDataBase64 = AesGcmCipher.encryptAsBase64(data, sessionKey, iv);

        return new EncryptionResult(
                new CipherRequestPayload(
                        new HandshakeContext(
                                negotiatedKeys.clientEphemeralPublicKeyBase64(),
                                ephemeralResponse.serverKeyTicketBase64()
                        ),
                        new CipherDataPayload(
                                EncodingUtils.toBase64(iv),
                                encryptedDataBase64
                        )
                ),
                new CryptoRequestContext(
                        UUID.randomUUID().toString(),
                        new SecretKeySpec(sessionKey.getEncoded(), CryptoConstants.ALGORITHM_AES),
                        iv,
                        negotiatedKeys.clientEphemeralPrivateKey(),
                        negotiatedKeys.serverEphemeralPublicKey(),
                        negotiatedKeys.sharedSecret()
                )
        );
    }

    /**
     * Creates a response-only session for ECDH encryption.
     * This method verifies the server's ephemeral public key signature, derives a shared secret,
     * and returns a ResponseOnlySession containing the plain request payload and the context needed for response decryption.
     *
     * @param demoPlainRequest The plain request payload to send in the response-only session.
     * @param ephemeralResponse The server's ephemeral public key response.
     * @param ecdsaResponse The server's ECDSA verification key response.
     * @return A ResponseOnlySession containing the request payload and context for response decryption.
     * @throws GeneralSecurityException If key negotiation or signature verification fails due to cryptographic errors.
     */
    public ResponseOnlySession createResponseOnlySession(
            DemoPlainRequest demoPlainRequest,
            EphemeralKeyResponse ephemeralResponse,
            VerificationKeyResponse ecdsaResponse
    ) throws GeneralSecurityException {
        log.debug("start to create response only session");
        verifyServerEphemeralPublicKey(ephemeralResponse, ecdsaResponse);
        NegotiatedKeys negotiatedKeys = negotiateKeys(ephemeralResponse.ephemeralPublicKeyBase64());
        return new ResponseOnlySession(
                new PlainRequestPayload(
                        new HandshakeContext(
                                negotiatedKeys.clientEphemeralPublicKeyBase64(),
                                ephemeralResponse.serverKeyTicketBase64()
                        ),
                        demoPlainRequest
                ),
                new CryptoRequestContext(
                        UUID.randomUUID().toString(),
                        null, // No session key is derived for response-only requests, as the server will derive its own session key for the response
                        null, // No IV is generated for response-only requests, as the server will generate its own IV for the response
                        negotiatedKeys.clientEphemeralPrivateKey(),
                        negotiatedKeys.serverEphemeralPublicKey(),
                        negotiatedKeys.sharedSecret()
                )
        );
    }

    /**
     * Decrypts the given CipherDataPayload using the response AES key derived from the shared secret.
     *
     * @param payload The CipherDataPayload containing the encrypted request and associated metadata.
     * @param context The CryptoRequestContext containing the shared secret or key agreement keys.
     * @return The decrypted plaintext request as a String.
     * @throws GeneralSecurityException If decryption fails due to cryptographic errors or missing keys.
     */
    public String decrypt(CipherDataPayload payload, CryptoRequestContext context) throws GeneralSecurityException {
        log.debug("start to decrypt payload using CryptoRequestContext");
        if (payload == null) {
            throw new IllegalArgumentException("payload cannot be null");
        }
        if (context == null) {
            throw new IllegalStateException("CryptoRequestContext is required for response decryption");
        }

        byte[] sharedSecret = context.sharedSecret();
        if (sharedSecret == null) {
            if (context.clientEphemeralPrivateKey() == null || context.serverEphemeralPublicKey() == null) {
                throw new IllegalStateException("No ECDH key agreement state available for response decryption");
            }
            sharedSecret = KeyAgreementService.deriveSharedSecret(
                    context.clientEphemeralPrivateKey(),
                    context.serverEphemeralPublicKey()
            );
        }

        log.debug("Deriving response AES key from sharedSecret, iv and hkdfInfo");
        SecretKey responseKey = KeyAgreementService.deriveAesKey(
                sharedSecret,
                EncodingUtils.fromBase64(payload.ivBase64()),
                CryptoConstants.HKDF_INFO_RESPONSE_AES_KEY
        );

        return AesGcmCipher.decryptFromBase64(
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
        log.debug("Start to negotiate ECDH keys with server ephemeral public key");
        // Decode the server's ephemeral public key from Base64 and create a PublicKey object
        PublicKey serverEphemeralPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(serverEphemeralPublicKeyBase64))
        );

        // Generate a new ephemeral key pair for the client using the same curve as the server
        KeyPair clientEphemeralKeyPair = KeyPairFactory.generateEphemeralKeyPair(secureRandom);

        String clientEphemeralPublicKeyBase64 = EncodingUtils.toBase64(clientEphemeralKeyPair.getPublic().getEncoded());
        PrivateKey clientEphemeralPrivateKey = clientEphemeralKeyPair.getPrivate();

        // Perform ECDH key agreement to derive the shared secret using the client's private key and the server's public key
        KeyAgreement keyAgreement = KeyAgreement.getInstance(CryptoConstants.ALGORITHM_ECDH);
        keyAgreement.init(clientEphemeralPrivateKey);
        keyAgreement.doPhase(serverEphemeralPublicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();

        // Return the negotiated keys containing the shared secret and the client's ephemeral public key in Base64
        return new NegotiatedKeys(
                sharedSecret,
                clientEphemeralPublicKeyBase64,
                clientEphemeralPrivateKey,
                serverEphemeralPublicKey
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
     * Verifies the server's ephemeral public key signature using the ECDSA verification key.
     */
    private void verifyServerEphemeralPublicKey(
            EphemeralKeyResponse ephemeralResponse,
            VerificationKeyResponse ecdsaResponse
    ) throws GeneralSecurityException {
        log.debug("start to verify server ephemeral public key signature using ECDSA public key");
        if (ephemeralResponse == null) {
            throw new GeneralSecurityException("ECDH ephemeral public key response is missing");
        }
        if (ecdsaResponse == null) {
            throw new GeneralSecurityException("Server ECDSA public key is required for ECDH signature verification");
        }
        if (ecdsaResponse.publicKeyBase64() == null || ecdsaResponse.publicKeyBase64().isBlank()) {
            throw new GeneralSecurityException("Server ECDSA public key is required for ECDH signature verification");
        }
        if (ephemeralResponse.signatureBase64() == null || ephemeralResponse.signatureBase64().isBlank()) {
            throw new GeneralSecurityException("Server ECDH signature is missing");
        }

        PublicKey ecdsaPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(ecdsaResponse.publicKeyBase64()))
        );
        Signature signature = Signature.getInstance(ephemeralResponse.signatureAlgorithm());
        signature.initVerify(ecdsaPublicKey);
        signature.update(EncodingUtils.fromBase64(ephemeralResponse.ephemeralPublicKeyBase64()));
        boolean verified = signature.verify(EncodingUtils.fromBase64(ephemeralResponse.signatureBase64()));
        if (!verified) {
            throw new GeneralSecurityException("Server ECDH ephemeral public key signature verification failed");
        }
    }

}
