package com.ikea.crypto.server;

import com.ikea.crypto.server.exception.CustomExceptionHandler;
import com.ikea.crypto.server.model.ErrorResult;
import com.ikea.crypto.stc.exception.InvalidCryptoPayloadException;
import com.ikea.crypto.stc.exception.InvalidKeyException;
import com.ikea.crypto.stc.exception.KeyExpiredException;
import com.ikea.crypto.stc.exception.KeyNotAvailableException;
import com.ikea.crypto.stc.model.PublicKeyResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.ServletWebRequest;

import static org.junit.jupiter.api.Assertions.*;

class CryptoExceptionHandlerTest {
    private final CustomExceptionHandler handler = new CustomExceptionHandler();

    @Test
    void serverDefinesExpiredAndInvalidKeyResponses() {
        PublicKeyResponse latest = new PublicKeyResponse("public-key", "ciam:2", 123456789L);
        var expired = handler.handleExpiredKey(new KeyExpiredException(latest));
        assertEquals(HttpStatus.BAD_REQUEST, expired.getStatusCode());
        assertEquals("false", expired.getHeaders().getFirst("X-STC-Encrypted"));
        assertEquals("no-store", expired.getHeaders().getFirst("Cache-Control"));
        assertEquals("KEY_EXPIRED", expired.getBody().code());
        assertEquals(latest, expired.getBody().data());

        var invalid = handler.handleInvalidKey(new InvalidKeyException());
        assertEquals(HttpStatus.BAD_REQUEST, invalid.getStatusCode());
        assertEquals("false", invalid.getHeaders().getFirst("X-STC-Encrypted"));
        assertEquals("INVALID_KEY", invalid.getBody().code());
        assertNull(invalid.getBody().data());
    }

    @Test
    void serverDefinesClientAndSanitizedInternalErrors() {
        var request = new ServletWebRequest(new MockHttpServletRequest("POST", "/crypto/server/request-only"));
        var client = handler.handleCryptoClientError(new InvalidCryptoPayloadException("bad payload"), request);
        assertEquals(HttpStatus.BAD_REQUEST, client.getStatusCode());
        assertEquals("false", client.getHeaders().getFirst("X-STC-Encrypted"));
        assertEquals("bad payload", ((ErrorResult) client.getBody()).getMessage());

        var internal = handler.handleCryptoServerError(new KeyNotAvailableException("Vault unreachable"), request);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, internal.getStatusCode());
        assertEquals("false", internal.getHeaders().getFirst("X-STC-Encrypted"));
        assertEquals("Cryptographic service internal error", ((ErrorResult) internal.getBody()).getMessage());
    }
}
