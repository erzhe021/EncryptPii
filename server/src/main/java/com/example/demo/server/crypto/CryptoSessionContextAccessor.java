package com.example.demo.server.crypto;

import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

public final class CryptoSessionContextAccessor {
    private CryptoSessionContextAccessor() {
    }

    public static void setCryptoSessionContext(CryptoSessionContext<?> context) {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes == null) {
            return;
        }
        requestAttributes.setAttribute(
                CryptoSessionContext.REQUEST_CONTEXT_KEY,
                context,
                RequestAttributes.SCOPE_REQUEST
        );
    }

    public static CryptoSessionContext<?> getCryptoSessionContext() {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes == null) {
            return null;
        }
        Object value = requestAttributes.getAttribute(
                CryptoSessionContext.REQUEST_CONTEXT_KEY,
                RequestAttributes.SCOPE_REQUEST
        );
        if (value instanceof CryptoSessionContext<?> sessionContext) {
            return sessionContext;
        }
        return null;
    }
}
