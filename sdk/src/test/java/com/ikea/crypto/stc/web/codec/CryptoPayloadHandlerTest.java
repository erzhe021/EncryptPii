package com.ikea.crypto.stc.web.codec;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.stc.exception.InvalidCryptoRequestException;
import com.ikea.crypto.stc.exception.ResponseEncryptionException;
import com.ikea.crypto.stc.key.CryptoServer;
import com.ikea.crypto.stc.model.SessionKeyHeaders;
import com.ikea.crypto.stc.session.CryptoSessionContext;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CryptoPayloadHandlerTest {

    private final CryptoServer cryptoServer = mock(CryptoServer.class);
    private final CryptoPayloadHandler handler = new CryptoPayloadHandler(cryptoServer, new ObjectMapper());
    private final SessionKeyHeaders headers = new SessionKeyHeaders("test:1", "wrapped");

    @AfterEach
    void clearRequestContext() {
        CryptoSessionContextAccessor.clearCryptoSessionContext();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void parsesExpectedEncryptedPayload() {
        CryptoSessionContext context = handler.createSessionContext(
                "{\"ivBase64\":\"iv\",\"encryptedDataBase64\":\"ciphertext\"}", headers);

        assertEquals("iv", context.requestPayload().ivBase64());
        assertEquals("ciphertext", context.requestPayload().encryptedDataBase64());
    }

    @Test
    void rejectsDuplicateFieldsAndTrailingJson() {
        assertThrows(InvalidCryptoRequestException.class, () -> handler.createSessionContext(
                "{\"ivBase64\":\"first\",\"ivBase64\":\"second\",\"encryptedDataBase64\":\"data\"}", headers));
        assertThrows(InvalidCryptoRequestException.class, () -> handler.createSessionContext(
                "{\"ivBase64\":\"iv\",\"encryptedDataBase64\":\"data\"} {}", headers));
    }

    @Test
    void rejectsMissingBodyOrHeaders() {
        assertThrows(InvalidCryptoRequestException.class, () -> handler.createSessionContext(null, headers));
        assertThrows(InvalidCryptoRequestException.class, () -> handler.createSessionContext(" ", headers));
        assertThrows(InvalidCryptoRequestException.class, () -> handler.createSessionContext("{}", null));
        assertThrows(InvalidCryptoRequestException.class, () -> handler.createResponseSessionContext(null));
    }

    @Test
    void encryptUsesCachedKeyOnlyForItsMatchingSessionContext() throws GeneralSecurityException {
        SecretKey staleKey = new SecretKeySpec(new byte[16], "AES");
        SecretKey expectedKey = new SecretKeySpec(new byte[16], "AES");
        CryptoSessionContext cachedContext = CryptoSessionContext.responseOnly(headers);
        SessionKeyHeaders differentHeaders = new SessionKeyHeaders("test:2", "other-wrapped");
        CryptoSessionContext requestedContext = CryptoSessionContext.responseOnly(differentHeaders);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        CryptoSessionContextAccessor.setCryptoSessionContext(cachedContext);
        CryptoSessionContextAccessor.setResolvedSessionKey(staleKey);
        when(cryptoServer.decryptSessionKeyToSecretKey("test:2", "other-wrapped")).thenReturn(expectedKey);

        handler.encrypt("response", requestedContext);

        verify(cryptoServer).decryptSessionKeyToSecretKey("test:2", "other-wrapped");
    }

    @Test
    void rejectsMissingContextWhenEncryptingResponse() {
        assertThrows(ResponseEncryptionException.class, () -> handler.encrypt("response", null));
    }
}
