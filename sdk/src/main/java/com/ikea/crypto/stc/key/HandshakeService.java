package com.ikea.crypto.stc.key;

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
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import com.ikea.crypto.stc.util.EncodingUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.security.SecureRandom;

@Slf4j
public class HandshakeService {

    public static final Duration DEFAULT_TICKET_TTL = Duration.ofMinutes(5);

    private final EcdsaSigningService ecdsaSigningService;
    private final AesTicketMasterService aesTicketMasterService;
    private final Duration ticketTtl;
    private final SecureRandom secureRandom;

    public HandshakeService(EcdsaSigningService ecdsaSigningService, AesTicketMasterService aesTicketMasterService) {
        this(ecdsaSigningService, aesTicketMasterService, DEFAULT_TICKET_TTL);
    }

    public HandshakeService(EcdsaSigningService ecdsaSigningService, AesTicketMasterService aesTicketMasterService, Duration ticketTtl) {
        if (ecdsaSigningService == null || ecdsaSigningService.getPrivateKey() == null || ecdsaSigningService.getPublicKey() == null) {
            throw new IllegalArgumentException("ECDSA signing service is required.");
        }
        if (aesTicketMasterService == null || aesTicketMasterService.getTicketMasterKey() == null) {
            throw new IllegalArgumentException("Ticket master service is required for stateless ephemeral key encryption.");
        }
        if (ticketTtl == null || ticketTtl.isZero() || ticketTtl.isNegative()) {
            throw new IllegalArgumentException("Ticket TTL must be greater than zero.");
        }
        this.ecdsaSigningService = ecdsaSigningService;
        this.aesTicketMasterService = aesTicketMasterService;
        this.ticketTtl = ticketTtl;
        this.secureRandom = new SecureRandom();
    }

    public VerificationKeyResponse getEcdsaPublicKey() {
        return ecdsaSigningService.toVerificationKeyResponse();
    }

    public EphemeralKeyResponse getEphemeralPublicKey() throws GeneralSecurityException {
        KeyPair ephemeralKeyPair = KeyPairFactory.generateEphemeralKeyPair();
        byte[] ephemeralPublicKeyBytes = ephemeralKeyPair.getPublic().getEncoded();
        String serverKeyTicketBase64 = aesTicketMasterService.packEphemeralPrivateKeyToTicket(ephemeralKeyPair.getPrivate(), ticketTtl);
        byte[] signatureBytes = ecdsaSigningService.sign(ephemeralPublicKeyBytes);

        return new EphemeralKeyResponse(
                EncodingUtils.toBase64(ephemeralPublicKeyBytes),
                CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA,
                EncodingUtils.toBase64(signatureBytes),
                serverKeyTicketBase64
        );
    }

    public String decrypt(CipherRequestPayload payload) throws GeneralSecurityException {
        validatePayload(payload);
        PrivateKey serverPrivateKey = aesTicketMasterService.unpackEphemeralPrivateKeyFromTicket(payload.handshakeContext().serverKeyTicketBase64());
        PublicKey clientEphemeralPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(payload.handshakeContext().clientEphemeralPublicKeyBase64()))
        );
        byte[] sharedSecret = KeyAgreementService.deriveSharedSecret(serverPrivateKey, clientEphemeralPublicKey);
        CryptoSessionContextAccessor.setSharedSecret(sharedSecret);

        SecretKey requestKey = KeyAgreementService.deriveAesKey(
                sharedSecret,
                EncodingUtils.fromBase64(payload.cipherDataPayload().ivBase64()),
                CryptoConstants.HKDF_INFO_REQUEST_AES_KEY
        );
        return AesGcmCipher.decryptFromBase64(
                payload.cipherDataPayload().encryptedDataBase64(),
                requestKey,
                payload.cipherDataPayload().ivBase64()
        );
    }

    public CipherDataPayload encryptWithHandshakeContext(String data, HandshakeContext handshakeContext) throws GeneralSecurityException {
        byte[] sharedSecret = CryptoSessionContextAccessor.getSharedSecret();
        if (sharedSecret != null) {
            byte[] iv = CryptoSessionMaterialFactory.generateIv(secureRandom);
            SecretKey responseKey = KeyAgreementService.deriveAesKey(
                    sharedSecret,
                    iv,
                    CryptoConstants.HKDF_INFO_RESPONSE_AES_KEY
            );
            return new CipherDataPayload(
                    EncodingUtils.toBase64(iv),
                    AesGcmCipher.encryptAsBase64(data, responseKey, iv)
            );
        }
        return encryptUsingKeyTicket(data, handshakeContext);
    }

    public void validatePayload(CipherRequestPayload payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Payload cannot be null");
        }
        if (payload.handshakeContext() == null) {
            throw new IllegalArgumentException("Handshake context cannot be null");
        }
        if (!StringUtils.hasLength(payload.handshakeContext().clientEphemeralPublicKeyBase64())) {
            throw new IllegalArgumentException("Client ephemeral public key is required for ECDH decryption but was not provided.");
        }
        if (!StringUtils.hasLength(payload.handshakeContext().serverKeyTicketBase64())) {
            throw new IllegalArgumentException("Key ticket is required in handshake context for stateless ECDH decryption.");
        }
        if (payload.cipherDataPayload() == null) {
            throw new IllegalArgumentException("AES cipher payload cannot be null");
        }
        if (!StringUtils.hasLength(payload.cipherDataPayload().ivBase64())) {
            throw new IllegalArgumentException("IV is required but was not provided.");
        }
        if (!StringUtils.hasLength(payload.cipherDataPayload().encryptedDataBase64())) {
            throw new IllegalArgumentException("Encrypted data is required but was not provided.");
        }
    }

    private CipherDataPayload encryptUsingKeyTicket(String data, HandshakeContext handshakeContext) throws GeneralSecurityException {
        PrivateKey serverPrivateKey = aesTicketMasterService.unpackEphemeralPrivateKeyFromTicket(handshakeContext.serverKeyTicketBase64());
        PublicKey clientEphemeralPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(handshakeContext.clientEphemeralPublicKeyBase64()))
        );
        byte[] iv = CryptoSessionMaterialFactory.generateIv(secureRandom);
        SecretKey responseKey = KeyAgreementService.deriveAesKey(
                serverPrivateKey,
                clientEphemeralPublicKey,
                iv,
                CryptoConstants.HKDF_INFO_RESPONSE_AES_KEY
        );
        return new CipherDataPayload(
                EncodingUtils.toBase64(iv),
                AesGcmCipher.encryptAsBase64(data, responseKey, iv)
        );
    }
}
