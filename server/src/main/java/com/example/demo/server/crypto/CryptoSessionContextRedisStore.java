package com.example.demo.server.crypto;

import com.example.demo.crypto.SessionKeyTransport;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhHandshakeContext;
import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Component
public class CryptoSessionContextRedisStore {

    private static final Duration CONTEXT_TTL = Duration.ofMinutes(10);
    private static final String CONTEXT_KEY_PREFIX = "crypto:session-context:";

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public CryptoSessionContextRedisStore(StringRedisTemplate redisTemplate, ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
        CryptoSessionContextAccessor.setRedisStore(this);
    }

    public void save(String requestId, CryptoSessionContext<?> context) {
        if (requestId == null || requestId.isBlank() || context == null) {
            return;
        }
        try {
            Map<String, Object> value = new HashMap<>();
            value.put("algorithm", context.algorithm().name());
            value.put("requestKeyMaterial", serializeRequestKeyMaterial(context));
            String json = objectMapper.writeValueAsString(value);
            redisTemplate.opsForValue().set(CONTEXT_KEY_PREFIX + requestId, json, CONTEXT_TTL);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize crypto session context for Redis", e);
        }
    }

    public CryptoSessionContext<?> load(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return null;
        }
        String json = redisTemplate.opsForValue().get(CONTEXT_KEY_PREFIX + requestId);
        if (json == null || json.isBlank()) {
            return null;
        }
        try {
            Map<String, Object> value = objectMapper.readValue(json, Map.class);
            if (value == null || value.isEmpty()) {
                return null;
            }
            String algorithmName = String.valueOf(value.get("algorithm"));
            Object rawMaterial = value.get("requestKeyMaterial");
            if (rawMaterial == null) {
                return null;
            }
            CryptoAlgorithm algorithm = CryptoAlgorithm.valueOf(algorithmName);
            Object material = materialFromJson(algorithm, rawMaterial);
            return new CryptoSessionContext<>(algorithm, material);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read crypto session context from Redis", e);
        }
    }

    public void clear(String requestId) {
        if (requestId == null || requestId.isBlank()) {
            return;
        }
        redisTemplate.delete(CONTEXT_KEY_PREFIX + requestId);
    }

    private Object serializeRequestKeyMaterial(CryptoSessionContext<?> context) {
        Object material = context.requestKeyMaterial();
        if (material == null) {
            return null;
        }
        return material;
    }

    private Object materialFromJson(CryptoAlgorithm algorithm, Object rawMaterial) {
        if (rawMaterial instanceof Map<?, ?> map) {
            return switch (algorithm) {
                case RSA -> {
                    if (map.containsKey("sessionKeyBase64") || map.containsKey("sessionIvBase64")) {
                        yield objectMapper.convertValue(map, SessionKeyTransport.class);
                    }
                    yield objectMapper.convertValue(map, RsaCipherPayload.class);
                }
                case ECDH -> {
                    if (map.containsKey("clientEphemeralPublicKeyBase64") && map.containsKey("serverEphemeralPublicKeyBase64")) {
                        yield objectMapper.convertValue(map, EcdhHandshakeContext.class);
                    }
                    yield objectMapper.convertValue(map, EcdhCipherPayload.class);
                }
            };
        }
        return rawMaterial;
    }
}
