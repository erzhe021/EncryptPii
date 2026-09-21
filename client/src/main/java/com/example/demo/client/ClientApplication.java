package com.example.demo.client;

import com.example.demo.crypto.HttpHybridCryptoClient;
import com.example.demo.crypto.HybridCipherPayload;
import com.example.demo.crypto.HybridCryptoClient;

import java.net.URI;

public class ClientApplication {
    public static void main(String[] args) throws Exception {
        URI serverBaseUri = URI.create("http://localhost:8080");
        runScenario(serverBaseUri, "RSA");
        runScenario(serverBaseUri, "ECDH");
    }

    private static void runScenario(URI serverBaseUri, String keyAlgorithm) throws Exception {
        HttpHybridCryptoClient httpClient = new HttpHybridCryptoClient(serverBaseUri, keyAlgorithm);
        HybridCryptoClient cryptoClient = new HybridCryptoClient(httpClient);

        HybridCipherPayload payload = cryptoClient.encryptPhone("13764641531");
        String decryptedPhone = httpClient.submitEncryptedPhone(payload);

        System.out.println("=== " + keyAlgorithm + " Client Request Payload ===");
        System.out.println("algorithm: " + payload.algorithm());
        System.out.println("clientEphemeralPublicKeyBase64: " + payload.clientEphemeralPublicKeyBase64());
        System.out.println("encryptedAesKeyBase64: " + payload.encryptedAesKeyBase64());
        System.out.println("ivBase64: " + payload.ivBase64());
        System.out.println("encryptedPhoneBase64: " + payload.encryptedPhoneBase64());
        System.out.println("=== " + keyAlgorithm + " Server Decryption Result ===");
        System.out.println("phoneNumber: " + decryptedPhone);
    }
}
