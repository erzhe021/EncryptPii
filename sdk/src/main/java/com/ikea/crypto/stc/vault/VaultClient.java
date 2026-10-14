package com.ikea.crypto.stc.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.exception.VaultCasMismatchException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatusCode;
import org.springframework.vault.VaultException;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.Versioned;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A client for interacting with HashiCorp Vault, providing methods to read and write secrets.
 */
@Slf4j
public class VaultClient {

    private final ObjectMapper objectMapper;
    private final VaultTemplate vaultTemplate;

    public VaultClient(VaultTemplate vaultTemplate) {
        this.objectMapper = new ObjectMapper();
        this.vaultTemplate = Objects.requireNonNull(vaultTemplate, "VaultTemplate is required to access Vault.");
    }

    public record VaultSecretEntry(JsonNode data, int version, String createdTime) {}

    public record VaultWriteResult(int version, String createdTime) {}

    public Optional<VaultSecretEntry> readSecretVersion(String path, Integer version) {
        try {
            KvPath kvPath = normalizePath(path);
            Versioned<Map<String, Object>> secret = version == null
                    ? vaultTemplate.opsForVersionedKeyValue(kvPath.mountPath()).get(kvPath.secretPath())
                    : vaultTemplate.opsForVersionedKeyValue(kvPath.mountPath()).get(kvPath.secretPath(), Versioned.Version.from(version));

            if (secret == null || secret.getData() == null) {
                return Optional.empty();
            }

            Versioned.Metadata metadata = secret.getMetadata();
            if (metadata != null && metadata.isDestroyed()) {
                return Optional.empty();
            }

            int resolvedVersion = metadata != null
                    ? metadata.getVersion().getVersion()
                    : version != null ? version : 1;
            String createdTime = metadata != null
                    ? metadata.getCreatedAt().toString()
                    : null;
            return Optional.of(new VaultSecretEntry(objectMapper.valueToTree(secret.getData()), resolvedVersion, createdTime));
        } catch (HttpClientErrorException.NotFound e) {
            return Optional.empty();
        } catch (VaultException e) {
            throw new IllegalStateException("Vault read secret failed for path " + path + ": " + e.getMessage(), e);
        }
    }

    public Optional<JsonNode> readSecret(String path) {
        return readSecretVersion(path, null).map(VaultSecretEntry::data);
    }

    public VaultWriteResult writeSecret(String path, Map<String, Object> data) {
        return writeSecret(path, data, null);
    }

    public VaultWriteResult writeSecret(String path, Map<String, Object> data, Integer cas) {
        try {
            KvPath kvPath = normalizePath(path);
            Versioned.Metadata metadata = vaultTemplate.opsForVersionedKeyValue(kvPath.mountPath())
                    .put(kvPath.secretPath(), cas == null ? data : Versioned.create(data, Versioned.Version.from(cas)));
            return toWriteResult(path, metadata);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatusCode.valueOf(400) && (cas != null || e.getResponseBodyAsString().contains("check-and-set"))) {
                throw new VaultCasMismatchException("Vault CAS check failed for path " + path + ": " + e.getResponseBodyAsString(),
                        cas != null ? cas : -1);
            }
            throw e;
        } catch (VaultException e) {
            if (cas != null && e.getMessage() != null && e.getMessage().contains("check-and-set")) {
                throw new VaultCasMismatchException("Vault CAS check failed for path " + path + ": " + e.getMessage(), cas);
            }
            throw new IllegalStateException("Vault write failed for path " + path + ": " + e.getMessage(), e);
        }
    }

    private VaultWriteResult toWriteResult(String path, Versioned.Metadata metadata) {
        int version = metadata != null ? metadata.getVersion().getVersion() : -1;
        String createdTime = metadata != null ? metadata.getCreatedAt().toString() : null;
        if (version <= 0) {
            Optional<VaultSecretEntry> latest = readSecretVersion(path, null);
            if (latest.isPresent()) {
                version = latest.get().version();
                createdTime = latest.get().createdTime();
            }
        }
        if (version <= 0) {
            throw new IllegalStateException("Failed to retrieve valid version from Vault after writing to path: " + path);
        }
        return new VaultWriteResult(version, createdTime);
    }

    private KvPath normalizePath(String path) {
        String normalized = path == null ? "" : path.trim();
        if (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        if (normalized.contains("/data/")) {
            String[] segments = normalized.split("/data/", 2);
            return new KvPath(segments[0], segments[1]);
        }
        int slashIndex = normalized.indexOf('/');
        if (slashIndex < 0) {
            return new KvPath(normalized, "");
        }
        return new KvPath(normalized.substring(0, slashIndex), normalized.substring(slashIndex + 1));
    }

    private record KvPath(String mountPath, String secretPath) {}
}
