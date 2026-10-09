package com.ikea.crypto.stc.key.rotation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.Map;

public final class RotationLog {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private RotationLog() {
    }

    public static String toJson(Map<String, ?> fields) {
        try {
            return OBJECT_MAPPER.writeValueAsString(fields);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize RSA key rotation log event", e);
        }
    }
}
