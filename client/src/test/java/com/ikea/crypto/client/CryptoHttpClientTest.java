package com.ikea.crypto.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ikea.crypto.client.core.CryptoHttpClient;
import com.ikea.crypto.common.model.CipherDataPayload;
import com.ikea.crypto.common.model.EphemeralKeyResponse;
import com.ikea.crypto.common.model.VerificationKeyResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CryptoHttpClientTest {

    private HttpClient mockHttpClient;
    private HttpResponse<String> mockHttpResponse;
    private ObjectMapper objectMapper;
    private CryptoHttpClient cryptoHttpClient;

    private static final String EPHEMERAL_PATH = "/crypto/server/ecdh/ephemeral-public-key";
    private static final String ECDSA_PATH = "/crypto/server/ecdh/ecdsa-public-key";

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        mockHttpClient = Mockito.mock(HttpClient.class);
        mockHttpResponse = Mockito.mock(HttpResponse.class);
        objectMapper = new ObjectMapper();
        cryptoHttpClient = new CryptoHttpClient(
                mockHttpClient,
                URI.create("http://localhost:9090"),
                objectMapper,
                EPHEMERAL_PATH,
                ECDSA_PATH
        );
    }

    @Test
    @SuppressWarnings("unchecked")
    void testFetchEphemeralPublicKey() throws Exception {
        EphemeralKeyResponse responseObj = new EphemeralKeyResponse(
                "server-ephemeral-key",
                "SHA256withECDSA",
                "signature-data",
                "ticket-123"
        );
        String json = objectMapper.writeValueAsString(responseObj);

        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body()).thenReturn(json);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);

        EphemeralKeyResponse result = cryptoHttpClient.fetchEphemeralPublicKey();
        assertNotNull(result);
        assertEquals("server-ephemeral-key", result.ephemeralPublicKeyBase64());
        assertEquals("ticket-123", result.serverKeyTicketBase64());

        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(mockHttpClient, times(1)).send(captor.capture(), any(HttpResponse.BodyHandler.class));
        assertEquals("GET", captor.getValue().method());
        assertEquals("http://localhost:9090" + EPHEMERAL_PATH, captor.getValue().uri().toString());
    }

    @Test
    @SuppressWarnings("unchecked")
    void testFetchEcdsaPublicKeyCaching() throws Exception {
        VerificationKeyResponse responseObj = new VerificationKeyResponse(
                "ecdsa-public-key-base64",
                "SHA256withECDSA",
                System.currentTimeMillis() + 60000 // expires in 1 minute
        );
        String json = objectMapper.writeValueAsString(responseObj);

        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body()).thenReturn(json);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);

        // First call should make an HTTP request
        VerificationKeyResponse result1 = cryptoHttpClient.fetchEcdsaPublicKey();
        assertNotNull(result1);
        assertEquals("ecdsa-public-key-base64", result1.publicKeyBase64());

        // Second call within TTL should return cached response without sending another HTTP request
        VerificationKeyResponse result2 = cryptoHttpClient.fetchEcdsaPublicKey();
        assertSame(result1, result2);

        verify(mockHttpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));

        // Clear cache and call again - should make a second HTTP request
        cryptoHttpClient.clearEcdsaKeyCache();
        VerificationKeyResponse result3 = cryptoHttpClient.fetchEcdsaPublicKey();
        assertNotNull(result3);
        verify(mockHttpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void testPostAndDeserialize() throws Exception {
        CipherDataPayload responsePayload = new CipherDataPayload("iv-base64", "encrypted-data-base64");
        String json = objectMapper.writeValueAsString(responsePayload);

        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body()).thenReturn(json);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);

        CipherDataPayload result = cryptoHttpClient.post(
                "/crypto/server/ecdh/bidirectional",
                "request-body",
                CipherDataPayload.class
        );

        assertNotNull(result);
        assertEquals("iv-base64", result.ivBase64());
        assertEquals("encrypted-data-base64", result.encryptedDataBase64());
    }

    @Test
    @SuppressWarnings("unchecked")
    void testHttpRequestNon200ThrowsException() throws Exception {
        when(mockHttpResponse.statusCode()).thenReturn(500);
        when(mockHttpResponse.body()).thenReturn("Internal Server Error");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);

        assertThrows(IllegalStateException.class, () ->
                cryptoHttpClient.fetchEphemeralPublicKey()
        );
    }
}
