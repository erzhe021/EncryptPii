package com.ikea.crypto.server;

import com.ikea.crypto.stc.config.VaultProperties;
import com.ikea.crypto.stc.vault.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class VaultKeyRepositoryTest {

    @Test
    void testResolveSecretPath() {
        VaultProperties properties = new VaultProperties();
        properties.setSecretPath("secret/data/crypto/default-key");
        properties.setKeyAlias("default-key");

        VaultClient client = new VaultClient(properties.getAddr());
        VaultAuthenticator auth = new VaultAuthenticator(properties, client);
        VaultKeyCodec codec = new VaultKeyCodec();
        VaultKeyRepository repository = new VaultKeyRepository(properties, client, auth, codec);

        // Default alias returns exact secret path
        assertEquals("secret/data/crypto/default-key", repository.resolveSecretPath(null));
        assertEquals("secret/data/crypto/default-key", repository.resolveSecretPath(""));
        assertEquals("secret/data/crypto/default-key", repository.resolveSecretPath("default-key"));

        // Custom alias replaces last segment
        assertEquals("secret/data/crypto/custom-alias", repository.resolveSecretPath("custom-alias"));
    }
}
