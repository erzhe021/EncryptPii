package com.ikea.crypto.server;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ikea.crypto.common.constant.CryptoConstants;
import com.ikea.crypto.common.util.EncodingUtils;
import com.ikea.crypto.server.service.KeyRing;
import com.ikea.crypto.server.vault.VaultKeyCodec;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class VaultKeyCodecTest {

    private final VaultKeyCodec codec = new VaultKeyCodec();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void testSerializeAndDeserializeKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        kpg.initialize(CryptoConstants.RSA_KEY_SIZE_BITS);
        KeyPair keyPair = kpg.generateKeyPair();

        Map<String, Object> map = codec.serializeKeyPair(keyPair);
        assertNotNull(map.get("publicKey"));
        assertNotNull(map.get("privateKey"));

        ObjectNode node = objectMapper.createObjectNode();
        node.put("publicKey", (String) map.get("publicKey"));
        node.put("privateKey", (String) map.get("privateKey"));

        String createdIso = "2026-09-29T00:00:00Z";
        KeyRing.KeyEntry entry = codec.deserializeKeyEntry(node, 1, createdIso, "test-key", 60000L);

        assertEquals("test-key:1", entry.metadata().keyId());
        assertEquals(1L, entry.metadata().version());
        assertNotNull(entry.publicKey());
        assertNotNull(entry.privateKey());
        assertEquals(EncodingUtils.toBase64(keyPair.getPublic().getEncoded()), EncodingUtils.toBase64(entry.publicKey().getEncoded()));
    }

    @Test
    void testParseCreatedTimeFallback() {
        long fallback = 123456789L;
        assertEquals(fallback, codec.parseCreatedTime(null, fallback));
        assertEquals(fallback, codec.parseCreatedTime("invalid-date", fallback));
        assertTrue(codec.parseCreatedTime("2026-09-29T00:00:00Z", fallback) > 0);
    }
}
