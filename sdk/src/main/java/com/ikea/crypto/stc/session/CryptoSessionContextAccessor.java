package com.ikea.crypto.stc.session;

import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import javax.crypto.SecretKey;

/**
 * Stores crypto state exclusively in the current Servlet request.
 */
public final class CryptoSessionContextAccessor {
    private static final String SESSION_KEY_ATTRIBUTE = "crypto.session.key";
    private static final String REQUEST_CONTEXT_KEY = "crypto.session.context";

    private CryptoSessionContextAccessor() {
    }

    public static void setCryptoSessionContext(CryptoSessionContext context) {
        setRequestAttribute(RequestContextHolder.currentRequestAttributes(), REQUEST_CONTEXT_KEY, context);
    }

    public static CryptoSessionContext getCryptoSessionContext() {
        RequestAttributes requestAttributes = currentRequestAttributes();
        if (requestAttributes != null) {
            Object value = requestAttributes.getAttribute(REQUEST_CONTEXT_KEY, RequestAttributes.SCOPE_REQUEST);
            return value instanceof CryptoSessionContext sessionContext ? sessionContext : null;
        }
        return null;
    }

    public static void setResolvedSessionKey(SecretKey sessionKey) {
        setRequestAttribute(RequestContextHolder.currentRequestAttributes(), SESSION_KEY_ATTRIBUTE, sessionKey);
    }

    public static SecretKey getResolvedSessionKey() {
        RequestAttributes requestAttributes = currentRequestAttributes();
        if (requestAttributes != null) {
            Object value = requestAttributes.getAttribute(SESSION_KEY_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
            return value instanceof SecretKey secretKey ? secretKey : null;
        }
        return null;
    }

    public static void clearCryptoSessionContext() {
        RequestAttributes requestAttributes = currentRequestAttributes();
        if (requestAttributes != null) {
            requestAttributes.removeAttribute(REQUEST_CONTEXT_KEY, RequestAttributes.SCOPE_REQUEST);
            requestAttributes.removeAttribute(SESSION_KEY_ATTRIBUTE, RequestAttributes.SCOPE_REQUEST);
        }
    }

    private static RequestAttributes currentRequestAttributes() {
        return RequestContextHolder.getRequestAttributes();
    }

    private static void setRequestAttribute(RequestAttributes requestAttributes, String name, Object value) {
        if (value == null) {
            requestAttributes.removeAttribute(name, RequestAttributes.SCOPE_REQUEST);
        } else {
            requestAttributes.setAttribute(name, value, RequestAttributes.SCOPE_REQUEST);
        }
    }
}
