package com.ikea.crypto.stc.vault;

import com.ikea.crypto.stc.config.KeyLifecycleProperties;
import com.ikea.crypto.stc.config.VaultProperties;
import com.ikea.crypto.stc.key.KeyRing;
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
public record VaultKeyRepository(VaultProperties vaultProperties,
                                 KeyLifecycleProperties lifecycleProperties,
                                 VaultClient vaultClient,
                                 VaultKeyCodec codec) {

    /**
     * Resolves the configured Vault secret path. This key ring uses one alias and one secret path.
     */
    public String resolveSecretPath(String alias) {
        if (alias != null && !alias.isBlank()
                && !vaultProperties.getKeyAlias().equals(alias.trim())) {
            throw new IllegalArgumentException(
                    "Key alias '" + alias.trim() + "' does not match the configured Vault alias '"
                            + vaultProperties.getKeyAlias() + "'");
        }
        return vaultProperties.getSecretPath();
    }

    /**
     * Reads raw secret version data from Vault. When version is null, reads latest.
     */
    public Optional<VaultClient.VaultSecretEntry> readSecretVersionRaw(String alias, Integer version) throws IOException {
        String secretPath = resolveSecretPath(alias);
        return vaultClient.readSecretVersion(secretPath, version);
    }

    /**
     * Reads and deserializes the latest key version from Vault.
     */
    public Optional<KeyRing.KeyEntry> readLatestKey(String alias) throws IOException, GeneralSecurityException {
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
        String effectiveAlias = (alias != null && !alias.isBlank()) ? alias.trim() : vaultProperties.getKeyAlias();
        KeyRing.KeyEntry keyEntry = codec.deserializeKeyEntry(
                entry.data(),
                entry.version(),
                entry.createdTime(),
                effectiveAlias,
                lifecycleProperties.getValidityMillis()
        );
        return Optional.of(keyEntry);
    }

    /**
     * Writes an RSA keypair to Vault KV v2 with optional Check-And-Set (CAS).
     */
    public VaultClient.VaultWriteResult writeKeyWithCas(String alias, KeyPair keyPair, Integer cas)
            throws IOException {
        String secretPath = resolveSecretPath(alias);
        Map<String, Object> payload = codec.serializeKeyPair(keyPair);

        VaultClient.VaultWriteResult result = vaultClient.writeSecret(secretPath, payload, cas);
        if (result.version() <= 0) {
            throw new IllegalStateException("Failed to retrieve valid version from Vault after writing to path: " + secretPath);
        }
        log.info("Saved key for alias '{}' to Vault path '{}', obtained latest version {}", alias, secretPath, result.version());
        return result;
    }
}
