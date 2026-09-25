package com.example.demo.server.crypto;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Setter;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.crypto.SecretKey;
import java.util.UUID;

public final class CryptoSessionContextAccessor {
    public static final String REQUEST_ID_HEADER = "X-Crypto-Request-Id";
    public static final String REQUEST_ID_ATTRIBUTE = "crypto.request.id";
    public static final String SESSION_KEY_ATTRIBUTE = "crypto.session.key";

    private static final ThreadLocal<CryptoSessionContext<?>> THREAD_LOCAL = new ThreadLocal<>();
    private static final ThreadLocal<SecretKey> SESSION_KEY_LOCAL = new ThreadLocal<>();
    @Setter
    private static volatile CryptoSessionContextRedisStore redisStore;

    private CryptoSessionContextAccessor() {
    }

    public static void setCryptoSessionContext(CryptoSessionContext<?> context) {
        THREAD_LOCAL.set(context);
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        String requestId = resolveRequestId(requestAttributes);
        if (requestId != null && redisStore != null) {
            redisStore.save(requestId, context);
        }
        if (requestAttributes != null) {
            requestAttributes.setAttribute(
                    CryptoSessionContext.REQUEST_CONTEXT_KEY,
                    context,
                    RequestAttributes.SCOPE_REQUEST
            );
            if (requestId != null) {
                requestAttributes.setAttribute(
                        REQUEST_ID_ATTRIBUTE,
                        requestId,
                        RequestAttributes.SCOPE_REQUEST
                );
            }
        }
    }

    public static CryptoSessionContext<?> getCryptoSessionContext() {
        CryptoSessionContext<?> threadLocalContext = THREAD_LOCAL.get();
        if (threadLocalContext != null) {
            return threadLocalContext;
        }

        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes != null) {
            Object value = requestAttributes.getAttribute(
                    CryptoSessionContext.REQUEST_CONTEXT_KEY,
                    RequestAttributes.SCOPE_REQUEST
            );
            if (value instanceof CryptoSessionContext<?> sessionContext) {
                THREAD_LOCAL.set(sessionContext);
                return sessionContext;
            }
        }

        String requestId = resolveRequestId(requestAttributes);
        if (requestId != null && redisStore != null) {
            CryptoSessionContext<?> redisContext = redisStore.load(requestId);
            if (redisContext != null) {
                THREAD_LOCAL.set(redisContext);
                return redisContext;
            }
        }
        return null;
    }

    public static void setResolvedSessionKey(SecretKey sessionKey) {
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
        String requestId = resolveRequestId(requestAttributes);
        if (redisStore != null && requestId != null) {
            redisStore.clear(requestId);
        }
    }

    private static String resolveRequestId(RequestAttributes requestAttributes) {
        if (requestAttributes == null) {
            return null;
        }
        Object requestIdValue = requestAttributes.getAttribute(REQUEST_ID_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        if (requestIdValue instanceof String requestId && !requestId.isBlank()) {
            return requestId;
        }
        if (requestAttributes instanceof ServletRequestAttributes servletRequestAttributes) {
            HttpServletRequest request = servletRequestAttributes.getRequest();
            String headerRequestId = request.getHeader(REQUEST_ID_HEADER);
            if (headerRequestId != null && !headerRequestId.isBlank()) {
                requestAttributes.setAttribute(REQUEST_ID_ATTRIBUTE, headerRequestId, RequestAttributes.SCOPE_REQUEST);
                return headerRequestId;
            }
            String forwardedRequestId = request.getHeader("X-Request-Id");
            if (forwardedRequestId != null && !forwardedRequestId.isBlank()) {
                requestAttributes.setAttribute(REQUEST_ID_ATTRIBUTE, forwardedRequestId, RequestAttributes.SCOPE_REQUEST);
                return forwardedRequestId;
            }
            String generatedRequestId = UUID.randomUUID().toString();
            requestAttributes.setAttribute(REQUEST_ID_ATTRIBUTE, generatedRequestId, RequestAttributes.SCOPE_REQUEST);
            return generatedRequestId;
        }
        String generatedRequestId = UUID.randomUUID().toString();
        requestAttributes.setAttribute(REQUEST_ID_ATTRIBUTE, generatedRequestId, RequestAttributes.SCOPE_REQUEST);
        return generatedRequestId;
    }
}
