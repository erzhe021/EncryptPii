package com.ikea.crypto.client;

import com.ikea.crypto.client.core.CryptoHttpClient;
import com.ikea.crypto.stc.constant.CryptoConstants;
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
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        keyGen.initialize(CryptoConstants.RSA_KEY_SIZE_BITS);
        keyPair = keyGen.generateKeyPair();
    }

    @Test
    void testConstruct() {
        cryptoHttpClient = new CryptoHttpClient(URI.create("http:/localhost:9090"), "/crypto/server/public-key");
        assertNotNull(cryptoHttpClient);
    }
}
