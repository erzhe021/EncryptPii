package com.ikea.crypto.server.context;

/**
 * Redis-backed session store removed intentionally.
 * Context is now request-scoped only, avoiding distributed-state complexity for this simplified deployment.
 */
public final class CryptoSessionContextRedisStore {
    private CryptoSessionContextRedisStore() {
    }
}
