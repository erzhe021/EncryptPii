package com.example.demo.client;

import com.example.demo.crypto.*;
import com.example.demo.crypto.ecdh.EcdhHttpCryptoClient;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhCryptoClient;
import com.example.demo.crypto.rsa.RsaHttpCryptoClient;
import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.crypto.rsa.RsaCryptoClient;

import java.net.URI;
import java.util.logging.Logger;

public class ClientApplication {

    private static final Logger LOGGER = Logger.getLogger(ClientApplication.class.getName());

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
        LOGGER.info("=== " + CryptoConstants.ALGORITHM_ECDH + " Client Request Payload ===");
        LOGGER.info("algorithm: " + payload.algorithm());
        LOGGER.info("clientEphemeralPublicKeyBase64: " + payload.clientEphemeralPublicKeyBase64());
        LOGGER.info("serverEphemeralPublicKeyBase64: " + payload.serverEphemeralPublicKeyBase64());
        LOGGER.info("ivBase64: " + payload.ivBase64());
        LOGGER.info("encryptedDataBase64: " + payload.encryptedDataBase64());
        LOGGER.info("=== " + CryptoConstants.ALGORITHM_ECDH + " Server Decryption Result ===");
        LOGGER.info("data: " + decryptedData);
    }

    private static void rsaTest(String data) throws Exception {
        RsaHttpCryptoClient httpClient = new RsaHttpCryptoClient(serverBaseUri);
        RsaCryptoClient cryptoClient = new RsaCryptoClient(httpClient);
        RsaCipherPayload payload = cryptoClient.encrypt(data);
        String decryptedData = httpClient.decryptEncryptedData(payload);

        LOGGER.info("=== " + CryptoConstants.ALGORITHM_RSA + " Client Request Payload ===");
        LOGGER.info("algorithm: " + payload.algorithm());
        LOGGER.info("encryptedAesKeyBase64: " + payload.encryptedAesKeyBase64());
        LOGGER.info("ivBase64: " + payload.ivBase64());
        LOGGER.info("encryptedDataBase64: " + payload.encryptedDataBase64());
        LOGGER.info("=== " + CryptoConstants.ALGORITHM_RSA + " Server Decryption Result ===");
        LOGGER.info("data: " + decryptedData);
    }
}
