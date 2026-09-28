package com.ikea.crypto.server.context;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * Utility class to manage the CryptoSessionContext and shared secret in a thread-local and request-scoped manner.
 */
@Slf4j
public final class CryptoSessionContextAccessor {
    public static final String SHARED_SECRET_ATTRIBUTE = "crypto.shared.secret";

    private static final ThreadLocal<CryptoSessionContext> THREAD_LOCAL = new ThreadLocal<>();
    private static final ThreadLocal<byte[]> SHARED_SECRET_LOCAL = new ThreadLocal<>();

    private CryptoSessionContextAccessor() {
    }

    public static void setCryptoSessionContext(CryptoSessionContext context) {
        THREAD_LOCAL.set(context);
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            requestAttributes.setAttribute(
                    CryptoSessionContext.REQUEST_CONTEXT_KEY,
                    context,
                    RequestAttributes.SCOPE_REQUEST
            );
        }
    }

    public static CryptoSessionContext getCryptoSessionContext() {
        CryptoSessionContext threadLocalContext = THREAD_LOCAL.get();
        if (threadLocalContext != null) {
            return threadLocalContext;
        }
        // If not found in thread-local, check the request attributes
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            Object value = requestAttributes.getAttribute(
                    CryptoSessionContext.REQUEST_CONTEXT_KEY,
                    RequestAttributes.SCOPE_REQUEST
            );
            if (value instanceof CryptoSessionContext sessionContext) {
                // Cache the context in the thread-local for faster access in subsequent calls within the same request
                THREAD_LOCAL.set(sessionContext);
                return sessionContext;
            }
        }
        return null;
    }

    public static void setSharedSecret(byte[] sharedSecret) {
        log.debug("Store the negotiated shared secret in the request-scoped context for potential reuse");
        if (sharedSecret == null) {
            SHARED_SECRET_LOCAL.remove();
            return;
        }
        SHARED_SECRET_LOCAL.set(sharedSecret);
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            requestAttributes.setAttribute(SHARED_SECRET_ATTRIBUTE, sharedSecret, RequestAttributes.SCOPE_REQUEST);
        }
    }

    public static byte[] getSharedSecret() {
        log.debug("Retrieve the negotiated shared secret from the request-scoped context");
        byte[] sharedSecret = SHARED_SECRET_LOCAL.get();
        if (sharedSecret != null) {
            return sharedSecret;
        }
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes == null) {
            return null;
        }
        Object value = requestAttributes.getAttribute(SHARED_SECRET_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        if (value instanceof byte[] bytes) {
            SHARED_SECRET_LOCAL.set(bytes);
            return bytes;
        }
        return null;
    }

    public static void clearCryptoSessionContext() {
        log.debug("Clear the crypto context from the request-scoped context");
        THREAD_LOCAL.remove();
        SHARED_SECRET_LOCAL.remove();
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            requestAttributes.removeAttribute(
                    CryptoSessionContext.REQUEST_CONTEXT_KEY,
                    RequestAttributes.SCOPE_REQUEST
            );
            requestAttributes.removeAttribute(SHARED_SECRET_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        }
    }
}
