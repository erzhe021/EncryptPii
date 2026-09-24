package com.example.demo.crypto;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpRequest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ClientPublicKeyTransportTest {

    @Test
    void shouldApplyPublicKeyHeadersToRequest() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        ClientPublicKeyTransport transport = ClientPublicKeyTransport.fromPublicKey(keyPair.getPublic(), CryptoConstants.ALGORITHM_RSA);
        HttpRequest request = transport.apply(HttpRequest.newBuilder(URI.create("http://localhost/test")))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

        assertNotNull(request.headers().firstValue(ClientPublicKeyTransport.HEADER_CLIENT_PUBLIC_KEY).orElse(null));
        assertEquals(EncodingUtils.toBase64(keyPair.getPublic().getEncoded()),
                request.headers().firstValue(ClientPublicKeyTransport.HEADER_CLIENT_PUBLIC_KEY).orElseThrow());
        assertEquals(CryptoConstants.ALGORITHM_RSA,
                request.headers().firstValue(ClientPublicKeyTransport.HEADER_CLIENT_PUBLIC_KEY_ALGORITHM).orElseThrow());
    }
}
