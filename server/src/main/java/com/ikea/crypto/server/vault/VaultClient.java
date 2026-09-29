package com.ikea.crypto.server.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/**
 * Lightweight HTTP client for HashiCorp Vault.
 * Supports Kubernetes authentication and KV v2 secret read/write operations.
 */
@Slf4j
public class VaultClient {

    private final String vaultAddr;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public VaultClient(String vaultAddr) {
        this.vaultAddr = vaultAddr.endsWith("/") ? vaultAddr.substring(0, vaultAddr.length() - 1) : vaultAddr;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Performs Vault Kubernetes authentication using the ServiceAccount JWT and configured role.
     * Endpoint: POST /v1/auth/kubernetes/login
     *
     * @param role Vault kubernetes role name
     * @param jwt  Kubernetes ServiceAccount JWT
     * @return Vault client_token
     */
    public String loginWithKubernetes(String role, String jwt) throws IOException, InterruptedException {
        String endpoint = vaultAddr + "/v1/auth/kubernetes/login";
        String requestBody = objectMapper.writeValueAsString(Map.of(
                "role", role,
                "jwt", jwt
        ));

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        log.debug("Calling Vault Kubernetes login endpoint: {}", endpoint);
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new IllegalStateException("Vault Kubernetes login failed with HTTP status " + response.statusCode()
                    + ": " + response.body());
        }

        JsonNode root = objectMapper.readTree(response.body());
        JsonNode clientTokenNode = root.path("auth").path("client_token");
        if (clientTokenNode.isMissingNode() || clientTokenNode.asText().isBlank()) {
            throw new IllegalStateException("Vault response did not contain client_token: " + response.body());
        }

        log.info("Successfully authenticated to Vault via Kubernetes auth method (role: {})", role);
        return clientTokenNode.asText();
    }

    public record VaultSecretEntry(JsonNode data, int version, String createdTime) {}

    public record VaultWriteResult(int version, String createdTime) {}

    /**
     * Reads a specific version of secret data from Vault KV v2 engine.
     * When version is null, the latest version is returned along with its metadata.
     *
     * @param vaultToken Vault client token
     * @param path       Secret path (e.g. secret/data/crypto/rsa-keys)
     * @param version    Optional version number (null for latest)
     * @return Optional containing the VaultSecretEntry, or empty if 404 or destroyed
     */
    public Optional<VaultSecretEntry> readSecretVersion(String vaultToken, String path, Integer version)
            throws IOException, InterruptedException {
        String cleanPath = path.startsWith("/") ? path.substring(1) : path;
        String endpoint = vaultAddr + "/v1/" + cleanPath + (version != null ? "?version=" + version : "");

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("X-Vault-Token", vaultToken)
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 404) {
            log.info("Vault secret path not found (404): {}", endpoint);
            return Optional.empty();
        }

        if (response.statusCode() != 200) {
            throw new IllegalStateException("Vault read secret failed with HTTP status " + response.statusCode()
                    + ": " + response.body());
        }

        JsonNode root = objectMapper.readTree(response.body());
        JsonNode dataWrapper = root.path("data");
        JsonNode dataNode = dataWrapper.path("data");
        if (dataNode.isMissingNode() || dataNode.isNull()) {
            if (dataWrapper.isObject() && !dataWrapper.has("metadata")) {
                return Optional.of(new VaultSecretEntry(dataWrapper, version != null ? version : 1, null));
            }
            return Optional.empty();
        }

        boolean destroyed = dataWrapper.path("metadata").path("destroyed").asBoolean(false);
        if (destroyed) {
            log.info("Vault secret version {} is destroyed, skipping: {}", version, endpoint);
            return Optional.empty();
        }

        int ver = dataWrapper.path("metadata").path("version").asInt(version != null ? version : 1);
        String createdTime = dataWrapper.path("metadata").path("created_time").asText(null);

        return Optional.of(new VaultSecretEntry(dataNode, ver, createdTime));
    }

    /**
     * Reads latest secret data from Vault KV v2 engine.
     * Endpoint: GET /v1/{path}
     *
     * @param vaultToken Vault client token
     * @param path       Secret path (e.g. secret/data/crypto/rsa-keys)
     * @return Optional containing the 'data' node under data.data, or empty if 404
     */
    public Optional<JsonNode> readSecret(String vaultToken, String path) throws IOException, InterruptedException {
        return readSecretVersion(vaultToken, path, null).map(VaultSecretEntry::data);
    }

    /**
     * Writes secret data to Vault KV v2 engine.
     * Endpoint: POST /v1/{path}
     *
     * @param vaultToken Vault client token
     * @param path       Secret path (e.g. secret/data/crypto/pii-transport-key)
     * @param data       Key-value pairs to store under "data"
     * @return VaultWriteResult containing the version assigned by Vault and createdTime
     */
    public VaultWriteResult writeSecret(String vaultToken, String path, Map<String, Object> data) throws IOException, InterruptedException {
        return writeSecret(vaultToken, path, data, null);
    }

    /**
     * Writes secret data to Vault KV v2 engine with optional Check-And-Set (CAS).
     * Endpoint: POST /v1/{path}
     *
     * @param vaultToken Vault client token
     * @param path       Secret path (e.g. secret/data/crypto/pii-transport-key)
     * @param data       Key-value pairs to store under "data"
     * @param cas        Optional expected current version for CAS validation. If 0, requires key to not exist.
     * @return VaultWriteResult containing the version assigned by Vault and createdTime
     * @throws VaultCasMismatchException if CAS parameter does not match current version
     */
    public VaultWriteResult writeSecret(String vaultToken, String path, Map<String, Object> data, Integer cas) throws IOException, InterruptedException {
        Map<String, Object> payload;
        if (cas != null) {
            payload = Map.of(
                    "data", data,
                    "options", Map.of("cas", cas)
            );
        } else {
            payload = Map.of("data", data);
        }
        return writeRaw(vaultToken, path, payload, cas);
    }

    /**
     * Writes raw JSON data to any Vault endpoint (such as sys or auth endpoints).
     * Endpoint: POST /v1/{path}
     *
     * @return VaultWriteResult containing the version assigned by Vault (if available) and createdTime
     */
    public VaultWriteResult writeRaw(String vaultToken, String path, Object payload) throws IOException, InterruptedException {
        return writeRaw(vaultToken, path, payload, null);
    }

    /**
     * Writes raw JSON data to any Vault endpoint with optional CAS check.
     * Endpoint: POST /v1/{path}
     */
    public VaultWriteResult writeRaw(String vaultToken, String path, Object payload, Integer cas) throws IOException, InterruptedException {
        String cleanPath = path.startsWith("/") ? path.substring(1) : path;
        String endpoint = vaultAddr + "/v1/" + cleanPath;

        String requestBody = objectMapper.writeValueAsString(payload);

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("X-Vault-Token", vaultToken)
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() == 400 && (cas != null || (response.body() != null && response.body().contains("check-and-set")))) {
            log.warn("Vault CAS check failed for path '{}' (expected cas={}): {}", cleanPath, cas, response.body());
            throw new VaultCasMismatchException("Vault CAS check failed for path " + cleanPath + ": " + response.body(),
                    cas != null ? cas : -1);
        }

        if (response.statusCode() != 200 && response.statusCode() != 204) {
            throw new IllegalStateException("Vault write failed with HTTP status " + response.statusCode()
                    + ": " + response.body());
        }

        int version = -1;
        String createdTime = null;
        if (response.body() != null && !response.body().isBlank()) {
            try {
                JsonNode root = objectMapper.readTree(response.body());
                JsonNode dataNode = root.path("data");
                if (dataNode.has("version")) {
                    version = dataNode.path("version").asInt(-1);
                }
                if (dataNode.has("created_time")) {
                    createdTime = dataNode.path("created_time").asText(null);
                }
            } catch (Exception e) {
                log.warn("Failed to parse Vault write response body: {}", response.body(), e);
            }
        }

        // If version could not be parsed from write response, query latest metadata from Vault KV v2
        if (version <= 0) {
            Optional<VaultSecretEntry> latest = readSecretVersion(vaultToken, cleanPath, null);
            if (latest.isPresent()) {
                version = latest.get().version();
                if (createdTime == null) {
                    createdTime = latest.get().createdTime();
                }
            }
        }

        log.info("Successfully wrote to Vault path: {}, version: {}", cleanPath, version);
        return new VaultWriteResult(version, createdTime);
    }
}
