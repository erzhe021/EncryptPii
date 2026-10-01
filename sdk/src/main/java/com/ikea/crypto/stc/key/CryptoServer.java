package com.ikea.crypto.stc.key;

import com.ikea.crypto.stc.model.CipherDataPayload;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.EphemeralKeyResponse;
import com.ikea.crypto.stc.model.HandshakeContext;
import com.ikea.crypto.stc.model.VerificationKeyResponse;
import com.ikea.crypto.stc.constant.CryptoConstants;
import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.stc.crypto.KeyAgreementService;
import com.ikea.crypto.stc.crypto.KeyPairFactory;
import com.ikea.crypto.stc.util.EncodingUtils;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
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

    public CryptoServer(PrivateKey ecdsaPrivateKey, PublicKey ecdsaPublicKey, SecretKey ticketMasterKey, Duration ticketTtl) {
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
        Files.createDirectories(keyDirectory);
        KeyPair ecdsaKeyPair = loadOrCreateLongLivedKeyPair(
                keyDirectory.resolve("ecdsa-private-key.pkcs8"),
                keyDirectory.resolve("ecdsa-public-key.x509")
        );
        SecretKey ticketMasterKey = loadOrCreateMasterKey(keyDirectory.resolve("ecdh-ticket-master-key.aes"));
        return new CryptoServer(ecdsaKeyPair.getPrivate(), ecdsaKeyPair.getPublic(), ticketMasterKey);
    }

    public VerificationKeyResponse getEcdsaPublicKey() {
        String keyId = "ecdsa-20261001";
        long expiresAt = System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000;
        return new VerificationKeyResponse(
                EncodingUtils.toBase64(ecdsaPublicKey.getEncoded()),
                keyId,
                expiresAt
        );
    }

    public EphemeralKeyResponse getEphemeralPublicKey() throws GeneralSecurityException {
        KeyPair ephemeralKeyPair = KeyPairFactory.generateEphemeralKeyPair();
        byte[] ephemeralPublicKeyBytes = ephemeralKeyPair.getPublic().getEncoded();
        String serverKeyTicketBase64 = packEphemeralPrivateKeyToTicket(ephemeralKeyPair.getPrivate(), ticketTtl);

        Signature signature = Signature.getInstance(CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA);
        signature.initSign(ecdsaPrivateKey);
        signature.update(ephemeralPublicKeyBytes);

        return new EphemeralKeyResponse(
                EncodingUtils.toBase64(ephemeralPublicKeyBytes),
                CryptoConstants.SIGNATURE_ALGORITHM_SHA256_WITH_ECDSA,
                EncodingUtils.toBase64(signature.sign()),
                serverKeyTicketBase64
        );
    }

    public String decrypt(CipherRequestPayload payload) throws GeneralSecurityException {
        validatePayload(payload);
        PrivateKey serverPrivateKey = unpackEphemeralPrivateKeyFromTicket(payload.handshakeContext().serverKeyTicketBase64());
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
        return new CipherDataPayload(
                EncodingUtils.toBase64(iv),
                AesGcmCipher.encryptAsBase64(data, responseKey, iv)
        );
    }

    private String packEphemeralPrivateKeyToTicket(PrivateKey privateKey, Duration ttl) throws GeneralSecurityException {
        byte[] privateKeyBytes = privateKey.getEncoded();
        long expiresAt = System.currentTimeMillis() + ttl.toMillis();
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES + privateKeyBytes.length);
        buffer.putLong(expiresAt);
        buffer.put(privateKeyBytes);
        byte[] iv = CryptoSessionMaterialFactory.generateIv(secureRandom);
        byte[] ciphertext = AesGcmCipher.encrypt(buffer.array(), ticketMasterKey, iv);
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        return EncodingUtils.toBase64(combined);
    }

    private PrivateKey unpackEphemeralPrivateKeyFromTicket(String serverKeyTicketBase64) throws GeneralSecurityException {
        if (!StringUtils.hasLength(serverKeyTicketBase64)) {
            throw new IllegalArgumentException("Key ticket is required for stateless ECDH decryption but was not provided.");
        }
        byte[] combined = EncodingUtils.fromBase64(serverKeyTicketBase64);
        if (combined.length < 12 + 16 + Long.BYTES) {
            throw new IllegalArgumentException("Invalid key ticket format");
        }
        byte[] iv = Arrays.copyOfRange(combined, 0, 12);
        byte[] ciphertext = Arrays.copyOfRange(combined, 12, combined.length);
        byte[] plaintext = AesGcmCipher.decrypt(ciphertext, ticketMasterKey, iv);
        ByteBuffer buffer = ByteBuffer.wrap(plaintext);
        long expiresAt = buffer.getLong();
        if (System.currentTimeMillis() > expiresAt) {
            throw new IllegalArgumentException("Ephemeral key ticket has expired");
        }
        byte[] privateKeyBytes = new byte[buffer.remaining()];
        buffer.get(privateKeyBytes);
        return KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC)
                .generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
    }

    private static SecretKey loadOrCreateMasterKey(Path keyPath) throws IOException {
        if (Files.exists(keyPath)) {
            return new SecretKeySpec(Files.readAllBytes(keyPath), CryptoConstants.ALGORITHM_AES);
        }
        byte[] keyBytes = new byte[CryptoConstants.MASTER_KEY_SIZE_BYTES];
        new SecureRandom().nextBytes(keyBytes);
        Files.write(keyPath, keyBytes);
        return new SecretKeySpec(keyBytes, CryptoConstants.ALGORITHM_AES);
    }

    private static KeyPair loadOrCreateLongLivedKeyPair(Path privateKeyPath, Path publicKeyPath) throws GeneralSecurityException, IOException {
        KeyFactory keyFactory = KeyFactory.getInstance(CryptoConstants.ALGORITHM_EC);
        if (Files.exists(privateKeyPath) && Files.exists(publicKeyPath)) {
            return new KeyPair(
                    keyFactory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(publicKeyPath))),
                    keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(privateKeyPath)))
            );
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_EC);
        generator.initialize(new ECGenParameterSpec(CryptoConstants.CURVE_ECDH));
        KeyPair keyPair = generator.generateKeyPair();
        Files.write(privateKeyPath, keyPair.getPrivate().getEncoded());
        Files.write(publicKeyPath, keyPair.getPublic().getEncoded());
        return keyPair;
    }
}
