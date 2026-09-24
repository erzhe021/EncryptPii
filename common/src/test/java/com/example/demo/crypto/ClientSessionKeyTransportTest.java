package com.example.demo.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.net.URI;
import java.net.http.HttpRequest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ClientSessionKeyTransportTest {

    @Test
    void shouldApplySessionKeyHeadersToRequest() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(CryptoConstants.ALGORITHM_AES);
        keyGenerator.init(CryptoConstants.AES_KEY_SIZE_BITS);
        SecretKey sessionKey = keyGenerator.generateKey();
        byte[] iv = new byte[CryptoConstants.GCM_IV_LENGTH_BYTES];
        for (int i = 0; i < iv.length; i++) {
            iv[i] = (byte) (i + 1);
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CryptoConstants.ALGORITHM_RSA);
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        ClientSessionKeyTransport transport = ClientSessionKeyTransport.fromGeneratedKey(sessionKey, iv, keyPair.getPublic());
        HttpRequest request = transport.apply(HttpRequest.newBuilder(URI.create("http://localhost/test")))
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

        assertNotNull(request.headers().firstValue(CryptoConstants.HEADER_CLIENT_SESSION_IV).orElse(null));
        assertNotNull(request.headers().firstValue(CryptoConstants.HEADER_CLIENT_SESSION_KEY).orElse(null));
        assertNotNull(request.headers().firstValue(CryptoConstants.HEADER_CLIENT_SESSION_KEY).orElse(null));
        assertNotEquals(EncodingUtils.toBase64(sessionKey.getEncoded()),
                request.headers().firstValue(CryptoConstants.HEADER_CLIENT_SESSION_KEY).orElseThrow());
    }
}
