package com.ikea.crypto.server;

import com.ikea.crypto.stc.exception.InvalidCryptoPayloadException;
import com.ikea.crypto.stc.exception.InvalidKeyException;
import com.ikea.crypto.stc.exception.KeyExpiredException;
import com.ikea.crypto.stc.exception.KeyNotAvailableException;
import com.ikea.crypto.stc.model.PublicKeyResponse;
import com.ikea.crypto.stc.web.advice.CryptoExceptionHandler;
import com.ikea.crypto.stc.web.model.CryptoErrorResponse;
import com.ikea.crypto.stc.web.model.KeyErrorResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.ServletWebRequest;

import static org.junit.jupiter.api.Assertions.*;

class CryptoExceptionHandlerTest {
    private final CryptoExceptionHandler handler = new CryptoExceptionHandler();

    @Test
    void keyErrorsUseProtocolSpecificResponses() {
        PublicKeyResponse latest = new PublicKeyResponse("public-key", "ciam:2", 123456789L, 123456000L);
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
    void clientAndServerCryptoErrorsUseSdkResponseFormat() {
        var request = new ServletWebRequest(new MockHttpServletRequest("POST", "/crypto/request"));
        var client = handler.handleCryptoClientError(new InvalidCryptoPayloadException("bad payload"), request);
        assertEquals(HttpStatus.BAD_REQUEST, client.getStatusCode());
        assertEquals("false", client.getHeaders().getFirst("X-STC-Encrypted"));
        assertEquals("bad payload", client.getBody().message());
        assertEquals("/crypto/request", client.getBody().path());

        var internal = handler.handleCryptoServerError(new KeyNotAvailableException("Vault unreachable"), request);
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, internal.getStatusCode());
        assertEquals("false", internal.getHeaders().getFirst("X-STC-Encrypted"));
        assertEquals("Cryptographic service internal error", internal.getBody().message());
        assertEquals("/crypto/request", internal.getBody().path());
    }

    @Test
    void errorResponsesExposeHttpStatusAndReason() {
        var request = new ServletWebRequest(new MockHttpServletRequest("POST", "/crypto/request"));
        CryptoErrorResponse body = handler.handleCryptoClientError(
                new InvalidCryptoPayloadException("bad payload"), request).getBody();

        assertNotNull(body);
        assertEquals(HttpStatus.BAD_REQUEST.value(), body.status());
        assertEquals(HttpStatus.BAD_REQUEST.getReasonPhrase(), body.error());
        assertNotNull(body.timestamp());
    }
}
