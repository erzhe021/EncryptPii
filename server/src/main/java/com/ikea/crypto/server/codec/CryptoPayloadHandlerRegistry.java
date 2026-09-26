package com.ikea.crypto.server.codec;

import com.ikea.crypto.server.model.CryptoAlgorithm;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Registry for CryptoPayloadHandler instances, allowing retrieval based on CryptoAlgorithm.
 */
public class CryptoPayloadHandlerRegistry {

    // The registry maintains a mapping of CryptoAlgorithm to their corresponding CryptoPayloadHandler.
    private final Map<CryptoAlgorithm, CryptoPayloadHandler> handlers;

    /**
     * Constructs a CryptoPayloadHandlerRegistry with the provided list of handlers.
     *
     * @param handlers List of CryptoPayloadHandler instances to be registered.
     */
    public CryptoPayloadHandlerRegistry(List<CryptoPayloadHandler> handlers) {
        this.handlers = new EnumMap<>(CryptoAlgorithm.class);
        for (CryptoPayloadHandler handler : handlers) {
            this.handlers.put(handler.algorithm(), handler);
        }
    }

    /**
     * Retrieves the CryptoPayloadHandler for the specified CryptoAlgorithm.
     *
     * @param algorithm The CryptoAlgorithm for which the handler is requested.
     * @return The corresponding CryptoPayloadHandler, or null if not found.
     */
    public CryptoPayloadHandler getRequiredHandler(CryptoAlgorithm algorithm) {
        CryptoPayloadHandler handler = handlers.get(algorithm);
        if (handler == null) {
            throw new IllegalStateException("No crypto payload handler registered for algorithm: " + algorithm);
        }
        return handler;
    }
}
