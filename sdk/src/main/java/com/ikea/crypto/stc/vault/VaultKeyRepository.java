package com.ikea.crypto.stc.vault;

import com.ikea.crypto.stc.config.VaultProperties;
import com.ikea.crypto.stc.key.KeyRing;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Map;
import java.util.Optional;

/**
 * Repository responsible for reading and writing RSA cryptographic keys to/from HashiCorp Vault KV v2.
 */
@Slf4j
public class VaultKeyRepository {

    @Getter
    private final VaultProperties properties;
    @Getter
    private final VaultClient vaultClient;
    @Getter
    private final VaultAuthenticator authenticator;
    @Getter
    private final VaultKeyCodec codec;

    public VaultKeyRepository(VaultProperties properties, VaultClient vaultClient, VaultAuthenticator authenticator, VaultKeyCodec codec) {
        this.properties = properties;
        this.vaultClient = vaultClient;
        this.authenticator = authenticator;
        this.codec = codec;
    }

    /**
     * Resolves the secret path in Vault for the given key alias.
     */
    public String resolveSecretPath(String alias) {
        if (alias == null || alias.isBlank() || alias.equals(properties.getKeyAlias())) {
            return properties.getSecretPath();
        }
        String defaultPath = properties.getSecretPath();
        int lastSlash = defaultPath.lastIndexOf('/');
        if (lastSlash >= 0) {
            return defaultPath.substring(0, lastSlash + 1) + alias;
        }
        return defaultPath + "-" + alias;
    }

    /**
     * Reads raw secret version data from Vault. When version is null, reads latest.
     */
    public Optional<VaultClient.VaultSecretEntry> readSecretVersionRaw(String alias, Integer version)
            throws IOException {
        String vaultToken = authenticator.authenticate();
        String secretPath = resolveSecretPath(alias);
        return vaultClient.readSecretVersion(vaultToken, secretPath, version);
    }

    /**
     * Reads and deserializes the latest key version from Vault.
     */
    public Optional<KeyRing.KeyEntry> readLatestKey(String alias) throws IOException, InterruptedException, GeneralSecurityException {
        return readKeyVersion(alias, null);
    }

    /**
     * Reads and deserializes a specific key version from Vault.
     */
    public Optional<KeyRing.KeyEntry> readKeyVersion(String alias, Integer version)
            throws IOException, GeneralSecurityException {
        Optional<VaultClient.VaultSecretEntry> entryOpt = readSecretVersionRaw(alias, version);
        if (entryOpt.isEmpty()) {
            return Optional.empty();
        }
        VaultClient.VaultSecretEntry entry = entryOpt.get();
        String effectiveAlias = (alias != null && !alias.isBlank()) ? alias.trim() : properties.getKeyAlias();
        KeyRing.KeyEntry keyEntry = codec.deserializeKeyEntry(
                entry.data(),
                entry.version(),
                entry.createdTime(),
                effectiveAlias,
                properties.getValidityMillis()
        );
        return Optional.of(keyEntry);
    }

    /**
     * Writes an RSA keypair to Vault KV v2 with optional Check-And-Set (CAS).
     */
    public VaultClient.VaultWriteResult writeKeyWithCas(String alias, KeyPair keyPair, Integer cas)
            throws IOException {
        String vaultToken = authenticator.authenticate();
        String secretPath = resolveSecretPath(alias);
        Map<String, Object> payload = codec.serializeKeyPair(keyPair);

        VaultClient.VaultWriteResult result = vaultClient.writeSecret(vaultToken, secretPath, payload, cas);
        if (result.version() <= 0) {
            throw new IllegalStateException("Failed to retrieve valid version from Vault after writing to path: " + secretPath);
        }
        log.info("Saved key for alias '{}' to Vault path '{}', obtained latest version {}", alias, secretPath, result.version());
        return result;
    }
}
