package com.ikea.crypto.server.service;

import com.ikea.crypto.common.crypto.KeyAgreementService;
import com.ikea.crypto.common.crypto.KeyPairFactory;
import com.ikea.crypto.common.model.*;
import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.common.crypto.AesGcmCipher;
import com.ikea.crypto.common.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Arrays;


@Slf4j
public class CryptoServer {

    public static final Duration DEFAULT_TICKET_TTL = Duration.ofMinutes(5);

    @Getter
    private final PrivateKey ecdsaPrivateKey;

    private final PublicKey ecdsaPublicKey;

    private final SecretKey ticketMasterKey;

    private final Duration ticketTtl;

    private final SecureRandom secureRandom;

    public CryptoServer(PrivateKey ecdsaPrivateKey, PublicKey ecdsaPublicKey, SecretKey ticketMasterKey) {
        this(ecdsaPrivateKey, ecdsaPublicKey, ticketMasterKey, DEFAULT_TICKET_TTL);
    }

    public CryptoServer(
            PrivateKey ecdsaPrivateKey,
            PublicKey ecdsaPublicKey,
            SecretKey ticketMasterKey,
            Duration ticketTtl
    ) {
        if (ecdsaPrivateKey == null || ecdsaPublicKey == null) {
            throw new IllegalArgumentException("ECDSA key pair is required.");
        }
        if (ticketMasterKey == null) {
            throw new IllegalArgumentException("Ticket master key is required for stateless ephemeral key encryption.");
        }
        if (ticketTtl == null || ticketTtl.isZero() || ticketTtl.isNegative()) {
            throw new IllegalArgumentException("Ticket TTL must be greater than zero.");
        }
        this.ecdsaPrivateKey = ecdsaPrivateKey;
        this.ecdsaPublicKey = ecdsaPublicKey;
        this.ticketMasterKey = ticketMasterKey;
        this.ticketTtl = ticketTtl;
        this.secureRandom = new SecureRandom();
    }

    public static CryptoServer create(Path keyDirectory) throws GeneralSecurityException, IOException {
        log.info("Creating stateless EcdhCryptoServer from keyDirectory={}", keyDirectory);
        ensureKeyDirectory(keyDirectory);
        KeyPair ecdsaKeyPair = loadOrCreateLongLivedKeyPair(
                keyDirectory.resolve("ecdsa-private-key.pkcs8"),
                keyDirectory.resolve("ecdsa-public-key.x509"),
                KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC)
        );
        SecretKey ticketMasterKey = loadOrCreateMasterKey(
                keyDirectory.resolve("ecdh-ticket-master-key.aes")
        );
        return new CryptoServer(ecdsaKeyPair.getPrivate(), ecdsaKeyPair.getPublic(), ticketMasterKey);
    }

    private static void ensureKeyDirectory(Path keyDirectory) throws IOException {
        Files.createDirectories(keyDirectory);
    }

    private static SecretKey loadOrCreateMasterKey(Path keyPath) throws IOException {
        if (Files.exists(keyPath)) {
            byte[] keyBytes = Files.readAllBytes(keyPath);
            return new SecretKeySpec(keyBytes, CryptoConstants.ALGORITHM_AES);
        }
        byte[] keyBytes = new byte[CryptoConstants.MASTER_KEY_SIZE_BYTES];
        new SecureRandom().nextBytes(keyBytes);
        Files.write(keyPath, keyBytes);
        return new SecretKeySpec(keyBytes, CryptoConstants.ALGORITHM_AES);
    }

    private static KeyPair loadOrCreateLongLivedKeyPair(
            Path privateKeyPath,
            Path publicKeyPath,
            KeyFactory keyFactory
    ) throws GeneralSecurityException, IOException {
        if (Files.exists(privateKeyPath) && Files.exists(publicKeyPath)) {
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(privateKeyPath)));
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(publicKeyPath)));
            return new KeyPair(publicKey, privateKey);
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyFactory.getAlgorithm());
        generator.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        KeyPair keyPair = generator.generateKeyPair();
        Files.write(privateKeyPath, keyPair.getPrivate().getEncoded());
        Files.write(publicKeyPath, keyPair.getPublic().getEncoded());
        return keyPair;
    }

    public VerificationKeyResponse getEcdsaPublicKey() {
        String keyId = "ecdsa-20261001";
        long expiresAt = System.currentTimeMillis() + 30 * 24 * 60 * 60 * 1000L;
        return new VerificationKeyResponse(
                EncodingUtils.toBase64(ecdsaPublicKey.getEncoded()),
                keyId,
                expiresAt
        );
    }

    public EphemeralKeyResponse getEphemeralPublicKey() throws GeneralSecurityException {
        KeyPair ephemeralKeyPair = KeyPairFactory.generateEphemeralKeyPair();
        byte[] ephemeralPublicKeyBytes = ephemeralKeyPair.getPublic().getEncoded();
        String ephemeralPublicKeyBase64 = EncodingUtils.toBase64(ephemeralPublicKeyBytes);

        String serverKeyTicketBase64 = packEphemeralPrivateKeyToTicket(ephemeralKeyPair.getPrivate(), ticketTtl);

        Signature signature = Signature.getInstance(CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA);
        signature.initSign(ecdsaPrivateKey);
        signature.update(ephemeralPublicKeyBytes);
        byte[] signatureBytes = signature.sign();
        String signatureBase64 = EncodingUtils.toBase64(signatureBytes);

        return new EphemeralKeyResponse(
                ephemeralPublicKeyBase64,
                CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA,
                signatureBase64,
                serverKeyTicketBase64
        );
    }

    public String decrypt(CipherRequestPayload payload) throws GeneralSecurityException {
        log.debug("start to decrypt EcdhCipherPayload");
        validatePayload(payload);

        String serverKeyTicketBase64 = payload.handshakeContext().serverKeyTicketBase64();
        PrivateKey serverPrivateKey = unpackEphemeralPrivateKeyFromTicket(serverKeyTicketBase64);

        PublicKey clientEphemeralPublicKey = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePublic(
                new X509EncodedKeySpec(EncodingUtils.fromBase64(payload.handshakeContext().clientEphemeralPublicKeyBase64()))
        );

        byte[] sharedSecret = KeyAgreementService.deriveSharedSecret(serverPrivateKey, clientEphemeralPublicKey);
        // Store the negotiated shared secret in the request-scoped context for reuse in response encryption
        CryptoSessionContextAccessor.setSharedSecret(sharedSecret);

        log.debug("Deriving request AES key from sharedSecret, iv and hkdfInfo");
        SecretKey requestKey = KeyAgreementService.deriveAesKey(
                sharedSecret,
                EncodingUtils.fromBase64(payload.cipherDataPayload().ivBase64()),
                CryptoConstants.HKDF_INFO_REQUEST_AES_KEY
        );

        return decryptWithAes(payload, requestKey);
    }

    public CipherDataPayload encryptWithEcdhHandshakeContext(String data, HandshakeContext handshakeContext) throws GeneralSecurityException {
        log.debug("start to encrypt using EcdhHandshakeContext");
        byte[] sharedSecret = CryptoSessionContextAccessor.getSharedSecret();
        if (sharedSecret != null) {
            log.debug("Reusing resolved shared secret from context to derive isolated response AES key");
            byte[] iv = CryptoSessionMaterialFactory.generateIv(secureRandom);
            SecretKey responseKey = KeyAgreementService.deriveAesKey(
                    sharedSecret,
                    iv,
                    CryptoConstants.HKDF_INFO_RESPONSE_AES_KEY
            );
            String encryptedDataBase64 = AesGcmCipher.encryptAsBase64(data, responseKey, iv);
            return new CipherDataPayload(
                    EncodingUtils.toBase64(iv),
                    encryptedDataBase64
            );
        }
        return encryptUsingKeyTicket(data, handshakeContext);
    }

    private CipherDataPayload encryptUsingKeyTicket(
            String data,
            HandshakeContext handshakeContext
    ) throws GeneralSecurityException {
        if (!StringUtils.hasLength(handshakeContext.clientEphemeralPublicKeyBase64())) {
            throw new IllegalArgumentException("Client ephemeral public key is required for response encryption");
        }
        PrivateKey serverPrivateKey = unpackEphemeralPrivateKeyFromTicket(handshakeContext.serverKeyTicketBase64());
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

        String encryptedDataBase64 = AesGcmCipher.encryptAsBase64(data, responseKey, iv);
        return new CipherDataPayload(
                EncodingUtils.toBase64(iv),
                encryptedDataBase64
        );
    }

    private String packEphemeralPrivateKeyToTicket(PrivateKey privateKey, Duration ttl) throws GeneralSecurityException {
        log.debug("Packing ephemeral private key into encrypted stateless ticket");
        byte[] privateKeyBytes = privateKey.getEncoded();
        long expiresAt = System.currentTimeMillis() + ttl.toMillis();

        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES + privateKeyBytes.length);
        buffer.putLong(expiresAt);
        buffer.put(privateKeyBytes);
        byte[] plaintext = buffer.array();

        byte[] iv = CryptoSessionMaterialFactory.generateIv(secureRandom);
        byte[] ciphertext = AesGcmCipher.encrypt(plaintext, ticketMasterKey, iv);

        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);

        return EncodingUtils.toBase64(combined);
    }

    private PrivateKey unpackEphemeralPrivateKeyFromTicket(String serverKeyTicketBase64) throws GeneralSecurityException {
        log.debug("Unpacking ephemeral private key from encrypted stateless ticket");
        if (!StringUtils.hasLength(serverKeyTicketBase64)) {
            throw new IllegalArgumentException("Key ticket is required for stateless ECDH decryption but was not provided.");
        }
        byte[] combined;
        try {
            combined = EncodingUtils.fromBase64(serverKeyTicketBase64);
        } catch (Exception e) {
            throw new IllegalArgumentException("Key ticket is not valid Base64", e);
        }
        if (combined.length < 12 + 16 + Long.BYTES) {
            throw new IllegalArgumentException("Invalid key ticket format");
        }
        byte[] iv = Arrays.copyOfRange(combined, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(combined, 12, combined.length);

        byte[] plaintext;
        try {
            plaintext = AesGcmCipher.decrypt(ciphertext, ticketMasterKey, iv);
        } catch (GeneralSecurityException e) {
            throw new GeneralSecurityException("Key ticket verification failed: invalid or tampered ticket", e);
        }

        ByteBuffer buffer = ByteBuffer.wrap(plaintext);
        long expiresAt = buffer.getLong();
        if (System.currentTimeMillis() > expiresAt) {
            throw new IllegalArgumentException("Ephemeral key ticket has expired");
        }

        byte[] privateKeyBytes = new byte[buffer.remaining()];
        buffer.get(privateKeyBytes);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC).generatePrivate(keySpec);
    }

    private void validatePayload(CipherRequestPayload payload) {
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

    private String decryptWithAes(CipherRequestPayload payload, SecretKey sessionKey) throws GeneralSecurityException {
        return AesGcmCipher.decryptFromBase64(
                payload.cipherDataPayload().encryptedDataBase64(),
                sessionKey,
                payload.cipherDataPayload().ivBase64()
        );
    }
}
