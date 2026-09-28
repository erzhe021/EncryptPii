package com.ikea.crypto.server;

import com.ikea.crypto.common.crypto.AesGcmCipher;
import com.ikea.crypto.common.crypto.CryptoSessionMaterialFactory;
import com.ikea.crypto.common.crypto.SessionKeyService;
import com.ikea.crypto.common.model.payload.CipherRequestPayload;
import com.ikea.crypto.common.model.payload.PublicKeyResponse;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.server.service.CryptoServer;
import com.ikea.crypto.server.vault.VaultClient;
import com.ikea.crypto.server.vault.VaultKeyRing;
import com.ikea.crypto.server.vault.VaultProperties;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class VaultMultiVersionGracePeriodTest {

    private HttpServer mockVault;
    private int vaultPort;
    private KeyPair keyPairV1;
    private KeyPair keyPairV2;
    private KeyPair keyPairV3;

    private final AtomicInteger requestedVersion0Count = new AtomicInteger(0);

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        keyPairV1 = kpg.generateKeyPair();
        keyPairV2 = kpg.generateKeyPair();
        keyPairV3 = kpg.generateKeyPair();

        long now = System.currentTimeMillis();
        long oneDay = 24L * 3600 * 1000;

        // V3: Created now, expires in 10 days (Active)
        long v3Created = now;
        long v3Expires = now + 10 * oneDay;

        // V2: Created 15 days ago, expired 5 days ago (Within 30-day grace period)
        long v2Created = now - 15 * oneDay;
        long v2Expires = now - 5 * oneDay;

        // V1: Created 50 days ago, expired 40 days ago (Beyond 30-day grace period)
        long v1Created = now - 50 * oneDay;
        long v1Expires = now - 40 * oneDay;

        mockVault = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        vaultPort = mockVault.getAddress().getPort();

        mockVault.createContext("/v1/secret/data/crypto/rsa-keys", exchange -> {
            URI requestUri = exchange.getRequestURI();
            String query = requestUri.getQuery();
            Integer version = null;
            if (query != null && query.startsWith("version=")) {
                version = Integer.parseInt(query.substring("version=".length()));
            }

            if (version != null && version == 0) {
                requestedVersion0Count.incrementAndGet();
            }

            int ver = (version != null) ? version : 3; // Latest version is 3
            KeyPair kp;
            long created;
            long expires;

            if (ver == 3) {
                kp = keyPairV3;
                created = v3Created;
                expires = v3Expires;
            } else if (ver == 2) {
                kp = keyPairV2;
                created = v2Created;
                expires = v2Expires;
            } else if (ver == 1) {
                kp = keyPairV1;
                created = v1Created;
                expires = v1Expires;
            } else {
                exchange.sendResponseHeaders(404, -1);
                return;
            }

            String pubBase64 = EncodingUtils.toBase64(kp.getPublic().getEncoded());
            String privBase64 = EncodingUtils.toBase64(kp.getPrivate().getEncoded());
            String createdIso = java.time.Instant.ofEpochMilli(created).toString();

            // Notice: DevOps only needs to store publicKey and privateKey!
            String responseBody = String.format("""
                    {
                      "data": {
                        "data": {
                          "publicKey": "%s",
                          "privateKey": "%s"
                        },
                        "metadata": {
                          "version": %d,
                          "created_time": "%s"
                        }
                      }
                    }
                    """, pubBase64, privBase64, ver, createdIso);

            byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });

        mockVault.start();
    }

    @AfterEach
    void tearDown() {
        if (mockVault != null) {
            mockVault.stop(0);
        }
    }

    @Test
    void testAutomaticMultiVersionLoadingAndGracePeriodFiltering() throws Exception {
        VaultProperties properties = new VaultProperties();
        properties.setEnabled(true);
        properties.setAddr("http://127.0.0.1:" + vaultPort);
        properties.setAuthMethod(VaultProperties.AuthMethod.TOKEN);
        properties.setToken("root");
        properties.setSecretPath("secret/data/crypto/rsa-keys");
        properties.setKeyAlias("rsa-key");
        properties.setValidityMillis(10L * 24 * 3600 * 1000); // 10 days validity
        properties.setGracePeriodMillis(30L * 24 * 3600 * 1000); // 30 days grace

        VaultClient vaultClient = new VaultClient(properties.getAddr());
        VaultKeyRing vaultKeyRing = new VaultKeyRing(properties, vaultClient);

        // Initialize: should load version 3 as active, version 2 as transition key, and stop at version 1
        vaultKeyRing.initialize();

        CryptoServer server = new CryptoServer(vaultKeyRing);

        // 1. Verify active key is version 3
        PublicKeyResponse activeKey = server.getPublicKey();
        assertEquals("rsa-key:3", activeKey.keyId());

        // 2. Verify version 2 (within grace period) is loaded and present
        assertTrue(vaultKeyRing.findKeyEntry("rsa-key:2").isPresent());

        // 3. Verify version 1 (expired beyond grace period) is NOT in key ring
        assertTrue(vaultKeyRing.findKeyEntry("rsa-key:1").isEmpty());

        // 4. Verify backtracking stopped early upon hitting expired version 1 (version 0 never requested)
        assertEquals(0, requestedVersion0Count.get());

        // 5. Test decrypting request encrypted with version 2 (historical transition key)
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey sessionKey = keyGenerator.generateKey();
        byte[] iv = CryptoSessionMaterialFactory.generateIv(new SecureRandom());

        String encSessionKeyV2 = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, keyPairV2.getPublic());
        String encDataV2 = AesGcmCipher.encryptAsBase64("data-from-v2-client", sessionKey, iv);

        CipherRequestPayload payloadV2 = new CipherRequestPayload(
                "rsa-key:2",
                encSessionKeyV2,
                EncodingUtils.toBase64(iv),
                encDataV2
        );
        String decryptedV2 = server.decrypt(payloadV2);
        assertEquals("data-from-v2-client", decryptedV2);

        // 6. Test decrypting request encrypted with active version 3
        String encSessionKeyV3 = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, keyPairV3.getPublic());
        String encDataV3 = AesGcmCipher.encryptAsBase64("data-from-v3-client", sessionKey, iv);

        CipherRequestPayload payloadV3 = new CipherRequestPayload(
                "rsa-key:3",
                encSessionKeyV3,
                EncodingUtils.toBase64(iv),
                encDataV3
        );
        String decryptedV3 = server.decrypt(payloadV3);
        assertEquals("data-from-v3-client", decryptedV3);

        // 7. Test request encrypted with expired version 1 fails to decrypt
        String encSessionKeyV1 = SessionKeyService.encryptSessionKeyAsBase64(sessionKey, keyPairV1.getPublic());
        String encDataV1 = AesGcmCipher.encryptAsBase64("data-from-v1-client", sessionKey, iv);

        CipherRequestPayload payloadV1 = new CipherRequestPayload(
                "rsa-key:1",
                encSessionKeyV1,
                EncodingUtils.toBase64(iv),
                encDataV1
        );
        assertThrows(GeneralSecurityException.class, () -> server.decrypt(payloadV1));
    }
}
