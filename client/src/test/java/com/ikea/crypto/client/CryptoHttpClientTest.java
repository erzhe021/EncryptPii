package com.ikea.crypto.client;

import com.ikea.crypto.client.core.CryptoHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

class CryptoHttpClientTest {

    private CryptoHttpClient cryptoHttpClient;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        keyPair = keyGen.generateKeyPair();
    }

    @Test
    void testConstruct() {
        cryptoHttpClient = new CryptoHttpClient(URI.create("http:/localhost:9090"), "/crypto/server/public-key");
        assertNotNull(cryptoHttpClient);
    }
}
