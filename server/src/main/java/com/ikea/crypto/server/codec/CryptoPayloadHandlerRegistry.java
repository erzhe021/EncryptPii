package com.ikea.crypto.server.codec;

import com.ikea.crypto.server.model.CryptoAlgorithm;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Registry for CryptoPayloadHandler instances, allowing retrieval based on CryptoAlgorithm.
 */
public class CryptoPayloadHandlerRegistry {

    private final Map<CryptoAlgorithm, CryptoPayloadHandler> handlers;

    public CryptoPayloadHandlerRegistry(List<CryptoPayloadHandler> handlers) {
        this.handlers = new EnumMap<>(CryptoAlgorithm.class);
        for (CryptoPayloadHandler handler : handlers) {
            this.handlers.put(handler.algorithm(), handler);
        }
    }

    public CryptoPayloadHandler getRequiredHandler(CryptoAlgorithm algorithm) {
        CryptoPayloadHandler handler = handlers.get(algorithm);
        if (handler == null) {
            throw new IllegalStateException("No crypto payload handler registered for algorithm: " + algorithm);
        }
        return handler;
    }
}
