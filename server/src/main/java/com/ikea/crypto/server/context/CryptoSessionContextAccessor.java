package com.ikea.crypto.server.context;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import javax.crypto.SecretKey;

/**
 * Request-scoped crypto context accessor.
 * The context is kept only within the current request lifecycle and does not depend on Redis or request IDs.
 */
@Slf4j
public final class CryptoSessionContextAccessor {
    public static final String SESSION_KEY_ATTRIBUTE = "crypto.session.key";

    private static final ThreadLocal<CryptoSessionContext<?>> THREAD_LOCAL = new ThreadLocal<>();
    private static final ThreadLocal<SecretKey> SESSION_KEY_LOCAL = new ThreadLocal<>();

    private CryptoSessionContextAccessor() {
    }

    public static void setCryptoSessionContext(CryptoSessionContext<?> context) {
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

    public static CryptoSessionContext<?> getCryptoSessionContext() {
        CryptoSessionContext<?> threadLocalContext = THREAD_LOCAL.get();
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
            if (value instanceof CryptoSessionContext<?> sessionContext) {
                // Cache the context in the thread-local for faster access in subsequent calls within the same request
                THREAD_LOCAL.set(sessionContext);
                return sessionContext;
            }
        }
        return null;
    }

    public static void setResolvedSessionKey(SecretKey sessionKey) {
        log.debug("Store the resolved session key in the request-scoped context for potential reuse");
        if (sessionKey == null) {
            SESSION_KEY_LOCAL.remove();
            return;
        }
        SESSION_KEY_LOCAL.set(sessionKey);
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            requestAttributes.setAttribute(SESSION_KEY_ATTRIBUTE, sessionKey, RequestAttributes.SCOPE_REQUEST);
        }
    }

    public static SecretKey getResolvedSessionKey() {
        log.debug("Retrieve the resolved session key from the request-scoped context");
        SecretKey sessionKey = SESSION_KEY_LOCAL.get();
        if (sessionKey != null) {
            return sessionKey;
        }
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes == null) {
            return null;
        }
        Object value = requestAttributes.getAttribute(SESSION_KEY_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        if (value instanceof SecretKey secretKey) {
            SESSION_KEY_LOCAL.set(secretKey);
            return secretKey;
        }
        return null;
    }

    public static void clearCryptoSessionContext() {
        log.debug("Clear the crypto context from the request-scoped context");
        THREAD_LOCAL.remove();
        SESSION_KEY_LOCAL.remove();
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            requestAttributes.removeAttribute(
                    CryptoSessionContext.REQUEST_CONTEXT_KEY,
                    RequestAttributes.SCOPE_REQUEST
            );
            requestAttributes.removeAttribute(SESSION_KEY_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        }
    }
}
