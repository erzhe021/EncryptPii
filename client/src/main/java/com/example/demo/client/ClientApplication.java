package com.example.demo.client;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhCryptoClient;
import com.example.demo.crypto.ecdh.EcdhHttpCryptoClient;
import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.crypto.rsa.RsaCryptoClient;
import com.example.demo.crypto.rsa.RsaHttpCryptoClient;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;

@Slf4j
public class ClientApplication {

    private static final URI serverBaseUri = URI.create("http://localhost:8080");

    public static void main(String[] args) throws Exception {
        String data = "Hello, World!";
        rsaTest(data);
        ecdhTest(data);
    }

    private static void ecdhTest(String data) throws Exception {
        EcdhHttpCryptoClient httpClient = new EcdhHttpCryptoClient(serverBaseUri);
        EcdhCryptoClient cryptoClient = new EcdhCryptoClient(httpClient);
        EcdhCipherPayload payload = cryptoClient.encrypt(data);
        String decryptedData = httpClient.decryptEncryptedData(payload);
        log.info("----------------------------------------------------------------------------------");
        log.info("=== {} Client Request Payload ===", CryptoConstants.ALGORITHM_ECDH);
        log.info("algorithm: {}", payload.algorithm());
        log.info("clientEphemeralPublicKeyBase64: {}", payload.clientEphemeralPublicKeyBase64());
        log.info("serverEphemeralPublicKeyBase64: {}", payload.serverEphemeralPublicKeyBase64());
        log.info("ivBase64: {}", payload.ivBase64());
        log.info("encryptedDataBase64: {}", payload.encryptedDataBase64());
        log.info("=== {} Server Decryption Result ===", CryptoConstants.ALGORITHM_ECDH);
        log.info("data: {}", decryptedData);
    }

    private static void rsaTest(String data) throws Exception {
        RsaHttpCryptoClient httpClient = new RsaHttpCryptoClient(serverBaseUri);
        RsaCryptoClient cryptoClient = new RsaCryptoClient(httpClient);
        RsaCipherPayload payload = cryptoClient.encrypt(data);
        String decryptedData = httpClient.decryptEncryptedData(payload);
        log.info("----------------------------------------------------------------------------------");
        log.info("=== {} Client Request Payload ===", CryptoConstants.ALGORITHM_RSA);
        log.info("algorithm: {}", payload.algorithm());
        log.info("encryptedAesKeyBase64: {}", payload.encryptedAesKeyBase64());
        log.info("ivBase64: {}", payload.ivBase64());
        log.info("encryptedDataBase64: {}", payload.encryptedDataBase64());
        log.info("=== {} Server Decryption Result ===", CryptoConstants.ALGORITHM_RSA);
        log.info("data: {}", decryptedData);
    }
}
