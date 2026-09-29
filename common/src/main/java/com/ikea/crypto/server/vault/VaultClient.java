package com.ikea.crypto.server.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.vault.VaultException;
import org.springframework.vault.authentication.KubernetesAuthentication;
import org.springframework.vault.authentication.KubernetesAuthenticationOptions;
import org.springframework.vault.authentication.SimpleSessionManager;
import org.springframework.vault.authentication.TokenAuthentication;
import org.springframework.vault.client.ClientHttpRequestFactoryFactory;
import org.springframework.vault.client.RestTemplateBuilder;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.ClientOptions;
import org.springframework.vault.support.SslConfiguration;
import org.springframework.vault.support.Versioned;
import org.springframework.web.client.HttpClientErrorException;

import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/**
 * Spring Vault based client for HashiCorp Vault KV v2 and Kubernetes auth.
 */
@Slf4j
public class VaultClient {

    private final URI vaultUri;
    private final ClientHttpRequestFactory requestFactory;
    private final ObjectMapper objectMapper;

    public VaultClient(String vaultAddr) {
        this.vaultUri = URI.create(vaultAddr);
        this.requestFactory = ClientHttpRequestFactoryFactory.create(
                new ClientOptions(Duration.ofSeconds(10), Duration.ofSeconds(10)),
                SslConfiguration.unconfigured()
        );
        this.objectMapper = new ObjectMapper();
    }

    public record VaultSecretEntry(JsonNode data, int version, String createdTime) {}

    public record VaultWriteResult(int version, String createdTime) {}

    public String loginWithKubernetes(String authPath, String role, String jwt) {
        KubernetesAuthenticationOptions options = KubernetesAuthenticationOptions.builder()
                .path(stripAuthPrefix(authPath))
                .role(role)
                .jwtSupplier(() -> jwt)
                .build();
        KubernetesAuthentication authentication = new KubernetesAuthentication(options, restTemplateBuilder().build());
        String token = authentication.login().getToken();
        if (token == null || token.isBlank()) {
            throw new IllegalStateException("Vault Kubernetes login did not return a client token");
        }
        log.info("Successfully authenticated to Vault via Kubernetes auth method (role: {})", role);
        return token;
    }

    public Optional<VaultSecretEntry> readSecretVersion(String vaultToken, String path, Integer version) {
        try {
            KvPath kvPath = normalizePath(path);
            Versioned<Map<String, Object>> secret = version == null
                    ? authenticatedTemplate(vaultToken).opsForVersionedKeyValue(kvPath.mountPath()).get(kvPath.secretPath())
                    : authenticatedTemplate(vaultToken).opsForVersionedKeyValue(kvPath.mountPath()).get(kvPath.secretPath(), Versioned.Version.from(version));

            if (secret == null || secret.getData() == null) {
                return Optional.empty();
            }

            Versioned.Metadata metadata = secret.getMetadata();
            if (metadata != null && metadata.isDestroyed()) {
                return Optional.empty();
            }

            int resolvedVersion = metadata != null && metadata.getVersion() != null
                    ? metadata.getVersion().getVersion()
                    : (version != null ? version : 1);
            String createdTime = metadata != null && metadata.getCreatedAt() != null
                    ? metadata.getCreatedAt().toString()
                    : null;
            return Optional.of(new VaultSecretEntry(objectMapper.valueToTree(secret.getData()), resolvedVersion, createdTime));
        } catch (HttpClientErrorException.NotFound e) {
            return Optional.empty();
        } catch (VaultException e) {
            throw new IllegalStateException("Vault read secret failed for path " + path + ": " + e.getMessage(), e);
        }
    }

    public Optional<JsonNode> readSecret(String vaultToken, String path) {
        return readSecretVersion(vaultToken, path, null).map(VaultSecretEntry::data);
    }

    public VaultWriteResult writeSecret(String vaultToken, String path, Map<String, Object> data) {
        return writeSecret(vaultToken, path, data, null);
    }

    public VaultWriteResult writeSecret(String vaultToken, String path, Map<String, Object> data, Integer cas) {
        try {
            KvPath kvPath = normalizePath(path);
            Versioned.Metadata metadata = authenticatedTemplate(vaultToken)
                    .opsForVersionedKeyValue(kvPath.mountPath())
                    .put(kvPath.secretPath(), cas == null ? data : Versioned.create(data, Versioned.Version.from(cas)));
            return toWriteResult(vaultToken, path, metadata);
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

    private VaultWriteResult toWriteResult(String vaultToken, String path, Versioned.Metadata metadata) {
        int version = metadata != null && metadata.getVersion() != null ? metadata.getVersion().getVersion() : -1;
        String createdTime = metadata != null && metadata.getCreatedAt() != null ? metadata.getCreatedAt().toString() : null;
        if (version <= 0 || createdTime == null) {
            Optional<VaultSecretEntry> latest = readSecretVersion(vaultToken, path, null);
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

    private VaultTemplate authenticatedTemplate(String vaultToken) {
        return new VaultTemplate(restTemplateBuilder(), new SimpleSessionManager(new TokenAuthentication(vaultToken)));
    }

    private RestTemplateBuilder restTemplateBuilder() {
        return RestTemplateBuilder.builder()
                .endpoint(org.springframework.vault.client.VaultEndpoint.from(vaultUri))
                .requestFactory(requestFactory);
    }

    private String stripAuthPrefix(String authPath) {
        if (authPath == null || authPath.isBlank()) {
            return "kubernetes";
        }
        String normalized = authPath.trim();
        return normalized.startsWith("auth/") ? normalized.substring("auth/".length()) : normalized;
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
