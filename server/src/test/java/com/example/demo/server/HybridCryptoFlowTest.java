package com.example.demo.server;

import com.example.demo.crypto.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.util.TestPropertyValues;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.test.context.ContextConfiguration;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SpringBootTest(
        classes = ServerApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT
)
@ContextConfiguration(initializers = HybridCryptoFlowTest.TestKeyDirectoryInitializer.class)
class HybridCryptoFlowTest {
    @Value("${local.server.port}")
    int port;

    @Test
    void shouldEncryptAndDecryptDataWithPerRequestAesKey() throws Exception {
        HttpHybridCryptoClient publicKeyProvider = new HttpHybridCryptoClient(
                URI.create("http://localhost:" + port)
        );
        HybridCryptoClient client = new HybridCryptoClient(publicKeyProvider);

        HybridCipherPayload firstPayload = client.encrypt("13800138000");
        HybridCipherPayload secondPayload = client.encrypt("13800138000");

        assertEquals("13800138000", publicKeyProvider.decryptEncryptedData(firstPayload));
        assertEquals("13800138000", publicKeyProvider.decryptEncryptedData(secondPayload));
        assertNotEquals(firstPayload.encryptedAesKeyBase64(), secondPayload.encryptedAesKeyBase64());
        assertNotEquals(firstPayload.ivBase64(), secondPayload.ivBase64());
    }

    @Test
    void shouldEncryptAndDecryptDataWithEcdhKeyAgreement() throws Exception {
        HttpHybridCryptoClient publicKeyProvider = new HttpHybridCryptoClient(
                URI.create("http://localhost:" + port),
                CryptoConstants.ALGORITHM_ECDH
        );
        HybridCryptoClient client = new HybridCryptoClient(publicKeyProvider);

        HybridCipherPayload firstPayload = client.encrypt("13800138000");
        HybridCipherPayload secondPayload = client.encrypt("13800138000");

        assertEquals("13800138000", publicKeyProvider.decryptEncryptedData(firstPayload));
        assertEquals("13800138000", publicKeyProvider.decryptEncryptedData(secondPayload));
        assertNotEquals(firstPayload.clientEphemeralPublicKeyBase64(), secondPayload.clientEphemeralPublicKeyBase64());
        assertNotEquals(firstPayload.ivBase64(), secondPayload.ivBase64());
    }

    @Test
    void shouldReusePersistedRsaKeyPair() throws Exception {
        Path keyDirectory = Files.createTempDirectory("hybrid-crypto-reuse");
        HybridCryptoServer firstServer = HybridCryptoServer.create(keyDirectory);
        HybridCryptoServer secondServer = HybridCryptoServer.create(keyDirectory);

        assertEquals(
                firstServer.rsaPublicKey().getEncoded().length,
                secondServer.rsaPublicKey().getEncoded().length
        );
        assertEquals(
                java.util.Base64.getEncoder().encodeToString(firstServer.rsaPublicKey().getEncoded()),
                java.util.Base64.getEncoder().encodeToString(secondServer.rsaPublicKey().getEncoded())
        );
    }

    static class TestKeyDirectoryInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
        @Override
        public void initialize(ConfigurableApplicationContext applicationContext) {
            try {
                Path keyDirectory = Files.createTempDirectory("spring-hybrid-crypto-test");
                TestPropertyValues.of("hybrid.crypto.key-directory=" + keyDirectory.toAbsolutePath())
                        .applyTo(applicationContext);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to initialize test key directory", e);
            }
        }
    }
}
