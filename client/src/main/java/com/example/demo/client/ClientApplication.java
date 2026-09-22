package com.example.demo.client;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.HttpHybridCryptoClient;
import com.example.demo.crypto.HybridCipherPayload;
import com.example.demo.crypto.HybridCryptoClient;

import java.net.URI;
import java.util.logging.Logger;

public class ClientApplication {
    private static final Logger LOGGER = Logger.getLogger(ClientApplication.class.getName());
    public static void main(String[] args) throws Exception {
        URI serverBaseUri = URI.create("http://localhost:8080");
        runScenario(serverBaseUri, CryptoConstants.ALGORITHM_RSA);
        runScenario(serverBaseUri, CryptoConstants.ALGORITHM_ECDH);
    }

    private static void runScenario(URI serverBaseUri, String keyAlgorithm) throws Exception {
        HttpHybridCryptoClient httpClient = new HttpHybridCryptoClient(serverBaseUri, keyAlgorithm);
        HybridCryptoClient cryptoClient = new HybridCryptoClient(httpClient);

        HybridCipherPayload payload = cryptoClient.encrypt("13764641531");
        String decryptedData = httpClient.decryptEncryptedData(payload);

        LOGGER.info("=== " + keyAlgorithm + " Client Request Payload ===");
        LOGGER.info("algorithm: " + payload.algorithm());
        LOGGER.info("clientEphemeralPublicKeyBase64: " + payload.clientEphemeralPublicKeyBase64());
        LOGGER.info("encryptedAesKeyBase64: " + payload.encryptedAesKeyBase64());
        LOGGER.info("ivBase64: " + payload.ivBase64());
        LOGGER.info("encryptedDataBase64: " + payload.encryptedDataBase64());
        LOGGER.info("=== " + keyAlgorithm + " Server Decryption Result ===");
        LOGGER.info("data: " + decryptedData);
    }
}
