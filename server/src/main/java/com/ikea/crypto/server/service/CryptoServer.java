package com.ikea.crypto.server.service;

import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.crypto.AesGcmCryptoService;
import com.ikea.crypto.common.crypto.SessionKeyService;
import com.ikea.crypto.common.model.payload.CipherRequestPayload;
import com.ikea.crypto.common.model.payload.PublicKeyResponse;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.server.context.CryptoSessionContextAccessor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Slf4j
public record CryptoServer(PrivateKey privateKey, PublicKey publicKey) {

    public PublicKeyResponse getPublicKey() {
        String keyId = "rsa-20261001";
        // Set the expiration time to one year from now (in milliseconds)
        long expiresAt = System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L;
        return new PublicKeyResponse(EncodingUtils.toBase64(publicKey.getEncoded()), keyId, expiresAt);
    }

    public static CryptoServer create(Path keyDirectory) throws GeneralSecurityException, IOException {
        log.info("Creating CryptoServer from keyDirectory={}", keyDirectory);
        Files.createDirectories(keyDirectory);
        KeyPair keyPair = loadOrCreateKeyPair(
                keyDirectory.resolve("rsa-private-key.pkcs8"),
                keyDirectory.resolve("rsa-public-key.x509")
        );
        return new CryptoServer(keyPair.getPrivate(), keyPair.getPublic());
    }

    private static KeyPair loadOrCreateKeyPair(Path privateKeyPath, Path publicKeyPath)
            throws GeneralSecurityException, IOException {
        KeyFactory keyFactory = KeyFactory.getInstance(CryptoConstants.ALGORITHM_RSA);
        if (Files.exists(privateKeyPath) && Files.exists(publicKeyPath)) {
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(privateKeyPath)));
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(publicKeyPath)));
            return new KeyPair(publicKey, privateKey);
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        Files.write(privateKeyPath, keyPair.getPrivate().getEncoded());
        Files.write(publicKeyPath, keyPair.getPublic().getEncoded());
        return keyPair;
    }

    public String decrypt(CipherRequestPayload payload) throws GeneralSecurityException {
        validatePayload(payload);
        SecretKey sessionKey = decryptSessionKeyToSecretKey(payload.encryptedSessionKeyBase64());
        // Store the resolved session key in the request-scoped context for potential reuse
        CryptoSessionContextAccessor.setResolvedSessionKey(sessionKey);
        return decryptWithAes(payload, sessionKey);
    }

    public byte[] decryptSessionKey(String encryptedSessionKeyBase64) throws GeneralSecurityException {
        return decryptSessionKeyToSecretKey(encryptedSessionKeyBase64).getEncoded();
    }

    public SecretKey decryptSessionKeyToSecretKey(String encryptedSessionKeyBase64) throws GeneralSecurityException {
        log.debug("start to decrypt session key from encryptedSessionKeyBase64");
        if (!StringUtils.hasLength(encryptedSessionKeyBase64)) {
            throw new IllegalArgumentException("Encrypted session key is required.");
        }
        return SessionKeyService.decryptSessionKeyBase64(encryptedSessionKeyBase64, privateKey);
    }

    public void validatePayload(CipherRequestPayload payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Payload cannot be null");
        }
        if (!StringUtils.hasLength(payload.encryptedSessionKeyBase64())) {
            throw new IllegalArgumentException("Encrypted AES key is required for RSA decryption but was not provided.");
        }
        if (!StringUtils.hasLength(payload.ivBase64())) {
            throw new IllegalArgumentException("IV is required but was not provided.");
        }
        if (!StringUtils.hasLength(payload.encryptedDataBase64())) {
            throw new IllegalArgumentException("Encrypted data is required but was not provided.");
        }
    }

    private String decryptWithAes(CipherRequestPayload payload, SecretKey sessionKey) throws GeneralSecurityException {
        return AesGcmCryptoService.decryptFromBase64(
                payload.encryptedDataBase64(),
                sessionKey,
                payload.ivBase64()
        );
    }
}
