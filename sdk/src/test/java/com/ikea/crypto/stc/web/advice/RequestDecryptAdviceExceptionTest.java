package com.ikea.crypto.stc.web.advice;

import com.ikea.crypto.stc.annotation.DecryptRequest;
import com.ikea.crypto.stc.exception.CryptoServerSideException;
import com.ikea.crypto.stc.exception.InvalidCryptoRequestException;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import com.ikea.crypto.stc.model.SessionKeyHeaders;
import com.ikea.crypto.stc.session.CryptoSessionContext;
import com.ikea.crypto.stc.session.CryptoSessionContextAccessor;
import com.ikea.crypto.stc.web.codec.CryptoPayloadHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.ServletWebRequest;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RequestDecryptAdviceExceptionTest {

    @AfterEach
    void clearCryptoSessionContext() {
        CryptoSessionContextAccessor.clearCryptoSessionContext();
    }

    @DecryptRequest
    public void endpoint(String body) {}

    @Test
    void rejectsNonJsonContentTypeForDecryptRequest() throws Exception {
        CryptoPayloadHandler handler = mock(CryptoPayloadHandler.class);
        MethodParameter parameter = new MethodParameter(
                getClass().getMethod("endpoint", String.class), 0);

        for (MediaType contentType : new MediaType[] {
                MediaType.APPLICATION_FORM_URLENCODED, MediaType.TEXT_PLAIN
        }) {
            MockHttpInputMessage input = new MockHttpInputMessage("body".getBytes(StandardCharsets.UTF_8));
            input.getHeaders().setContentType(contentType);
            input.getHeaders().set("X-STC-Enabled", "true");
            assertThrows(InvalidCryptoRequestException.class,
                    () -> new RequestDecryptAdvice(handler).beforeBodyRead(
                            input, parameter, String.class, StringHttpMessageConverter.class));
        }
        verifyNoInteractions(handler);
    }

    @Test
    void cryptoInfrastructureFailureReturnsGeneric500() throws Exception {
        CryptoPayloadHandler handler = mock(CryptoPayloadHandler.class);
        CryptoSessionContext context = CryptoSessionContext.request(
                new CipherRequestPayload("iv", "data"), new SessionKeyHeaders("test:1", "wrapped"));
        when(handler.createSessionContext(anyString(), any(SessionKeyHeaders.class))).thenReturn(context);
        NoSuchAlgorithmException cause = new NoSuchAlgorithmException("Provider details");
        when(handler.decrypt(context)).thenThrow(cause);
        CryptoServerSideException exception = assertThrows(CryptoServerSideException.class,
                () -> invoke(handler));
        assertSame(cause, exception.getCause());

        var response = new CryptoExceptionHandler().handleCryptoServerError(
                exception, new ServletWebRequest(new MockHttpServletRequest()));
        assertEquals(500, response.getStatusCode().value());
        assertEquals("false", response.getHeaders().getFirst("X-STC-Encrypted"));
        assertNotNull(response.getBody());
        assertEquals("Cryptographic service internal error", response.getBody().message());
    }

    @Test
    void requestFormatFailureRemains400WithoutWrapping() throws Exception {
        CryptoPayloadHandler handler = mock(CryptoPayloadHandler.class);
        InvalidCryptoRequestException cause = new InvalidCryptoRequestException("Invalid request");
        when(handler.createSessionContext(anyString(), any(SessionKeyHeaders.class))).thenThrow(cause);
        assertSame(cause, assertThrows(InvalidCryptoRequestException.class, () -> invoke(handler)));
        var response = new CryptoExceptionHandler().handleCryptoClientError(
                cause, new ServletWebRequest(new MockHttpServletRequest()));
        assertEquals(400, response.getStatusCode().value());
    }

    private void invoke(CryptoPayloadHandler handler) throws Exception {
        MockHttpInputMessage input = new MockHttpInputMessage("body".getBytes(StandardCharsets.UTF_8));
        input.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        input.getHeaders().set("X-STC-Enabled", "true");
        input.getHeaders().set("X-STC-Key-Id", "test:1");
        input.getHeaders().set("X-STC-Session-Key", "wrapped");
        MethodParameter parameter = new MethodParameter(
                getClass().getMethod("endpoint", String.class), 0);
        new RequestDecryptAdvice(handler).beforeBodyRead(
                input, parameter, String.class, StringHttpMessageConverter.class);
    }
}
