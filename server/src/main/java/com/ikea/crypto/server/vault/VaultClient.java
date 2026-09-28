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

    /**
     * Reads secret data from Vault KV v2 engine.
     * Endpoint: GET /v1/{path}
     *
     * @param vaultToken Vault client token
     * @param path       Secret path (e.g. secret/data/crypto/rsa-keys)
     * @return Optional containing the 'data' node under data.data, or empty if 404
     */
    public Optional<JsonNode> readSecret(String vaultToken, String path) throws IOException, InterruptedException {
        String cleanPath = path.startsWith("/") ? path.substring(1) : path;
        String endpoint = vaultAddr + "/v1/" + cleanPath;

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
        // In KV v2, the payload is located at root.data.data
        JsonNode dataNode = root.path("data").path("data");
        if (dataNode.isMissingNode() || dataNode.isNull()) {
            return Optional.empty();
        }
        return Optional.of(dataNode);
    }

    /**
     * Writes secret data to Vault KV v2 engine.
     * Endpoint: POST /v1/{path}
     *
     * @param vaultToken Vault client token
     * @param path       Secret path (e.g. secret/data/crypto/rsa-keys)
     * @param data       Key-value pairs to store under "data"
     */
    public void writeSecret(String vaultToken, String path, Map<String, Object> data) throws IOException, InterruptedException {
        writeRaw(vaultToken, path, Map.of("data", data));
    }

    /**
     * Writes raw JSON data to any Vault endpoint (such as sys or auth endpoints).
     * Endpoint: POST /v1/{path}
     */
    public void writeRaw(String vaultToken, String path, Object payload) throws IOException, InterruptedException {
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

        if (response.statusCode() != 200 && response.statusCode() != 204) {
            throw new IllegalStateException("Vault write failed with HTTP status " + response.statusCode()
                    + ": " + response.body());
        }

        log.info("Successfully wrote to Vault path: {}", cleanPath);
    }
}
