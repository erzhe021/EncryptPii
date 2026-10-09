package com.ikea.crypto.server;

import com.ikea.crypto.server.exception.CustomExceptionHandler;
import com.ikea.crypto.server.model.ErrorResult;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.ServletWebRequest;

import java.security.GeneralSecurityException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CustomExceptionHandlerTest {
    private final CustomExceptionHandler handler = new CustomExceptionHandler();

    @Test
    void applicationGeneralSecurityExceptionUsesApplicationFallback() {
        var request = new ServletWebRequest(new MockHttpServletRequest("POST", "/app/secure-operation"));
        var response = handler.handleUnspecificException(
                new GeneralSecurityException("application security operation failed"), request);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(
                "application security operation failed",
                ((ErrorResult) response.getBody()).getMessage()
        );
        assertEquals("/app/secure-operation", ((ErrorResult) response.getBody()).getPath());
    }
}
