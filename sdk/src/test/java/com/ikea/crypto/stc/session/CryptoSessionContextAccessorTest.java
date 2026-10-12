package com.ikea.crypto.stc.session;

import com.ikea.crypto.stc.model.SessionKeyHeaders;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.crypto.spec.SecretKeySpec;

import static org.junit.jupiter.api.Assertions.*;

class CryptoSessionContextAccessorTest {

    @AfterEach
    void resetRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void stateIsIsolatedBetweenServletRequests() {
        ServletRequestAttributes first = bindRequest();
        CryptoSessionContext context = CryptoSessionContext.responseOnly(new SessionKeyHeaders("test:1", "wrapped"));
        SecretKeySpec key = new SecretKeySpec(new byte[32], "AES");
        CryptoSessionContextAccessor.setCryptoSessionContext(context);
        CryptoSessionContextAccessor.setResolvedSessionKey(key);

        bindRequest();
        assertNull(CryptoSessionContextAccessor.getCryptoSessionContext());
        assertNull(CryptoSessionContextAccessor.getResolvedSessionKey());

        RequestContextHolder.setRequestAttributes(first);
        assertSame(context, CryptoSessionContextAccessor.getCryptoSessionContext());
        assertSame(key, CryptoSessionContextAccessor.getResolvedSessionKey());
        CryptoSessionContextAccessor.clearCryptoSessionContext();
        assertNull(CryptoSessionContextAccessor.getCryptoSessionContext());
        assertNull(CryptoSessionContextAccessor.getResolvedSessionKey());
    }

    @Test
    void nullValuesRemoveRequestState() {
        bindRequest();
        CryptoSessionContextAccessor.setCryptoSessionContext(
                CryptoSessionContext.responseOnly(new SessionKeyHeaders("test:1", "wrapped")));
        CryptoSessionContextAccessor.setResolvedSessionKey(new SecretKeySpec(new byte[32], "AES"));

        CryptoSessionContextAccessor.setCryptoSessionContext(null);
        CryptoSessionContextAccessor.setResolvedSessionKey(null);

        assertNull(CryptoSessionContextAccessor.getCryptoSessionContext());
        assertNull(CryptoSessionContextAccessor.getResolvedSessionKey());
    }

    @Test
    void writesRequireAnActiveRequest() {
        RequestContextHolder.resetRequestAttributes();
        assertThrows(IllegalStateException.class, () -> CryptoSessionContextAccessor.setCryptoSessionContext(
                CryptoSessionContext.responseOnly(new SessionKeyHeaders("test:1", "wrapped"))));
        assertThrows(IllegalStateException.class, () -> CryptoSessionContextAccessor.setResolvedSessionKey(
                new SecretKeySpec(new byte[32], "AES")));
        assertNull(CryptoSessionContextAccessor.getCryptoSessionContext());
        assertNull(CryptoSessionContextAccessor.getResolvedSessionKey());
        assertDoesNotThrow(CryptoSessionContextAccessor::clearCryptoSessionContext);
    }

    @Test
    void headersRejectInvalidValuesAtConstruction() {
        assertThrows(com.ikea.crypto.stc.exception.InvalidCryptoPayloadException.class,
                () -> new SessionKeyHeaders(" ", "wrapped"));
        assertThrows(com.ikea.crypto.stc.exception.InvalidCryptoPayloadException.class,
                () -> new SessionKeyHeaders("test:1", null));
    }

    private ServletRequestAttributes bindRequest() {
        ServletRequestAttributes attributes = new ServletRequestAttributes(new MockHttpServletRequest());
        RequestContextHolder.setRequestAttributes(attributes);
        return attributes;
    }
}
