package com.ikea.crypto.client;

import com.ikea.crypto.client.context.CryptoRequestContext;
import com.ikea.crypto.client.model.SessionKeyTransport;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;

import static org.junit.jupiter.api.Assertions.*;

class CryptoRequestContextTest {

    @Test
    void comparesArrayContentsAndProducesConsistentHashCodes() {
        var key = new SecretKeySpec(new byte[16], "AES");
        var transport = new SessionKeyTransport("key:1", "wrapped-key");
        var context = new CryptoRequestContext("request", key, new byte[]{1, 2, 3}, transport);
        var equalContext = new CryptoRequestContext("request", key, new byte[]{1, 2, 3}, transport);

        assertEquals(context, context);
        assertEquals(context, equalContext);
        assertEquals(equalContext, context);
        assertEquals(context.hashCode(), equalContext.hashCode());
        assertNotEquals(context, new CryptoRequestContext("request", key, new byte[]{1, 2, 4}, transport));
        assertNotEquals(context, new CryptoRequestContext("other", key, new byte[]{1, 2, 3}, transport));
        assertNotEquals(context, new CryptoRequestContext("request",
                new SecretKeySpec(new byte[24], "AES"), new byte[]{1, 2, 3}, transport));
        assertNotEquals(context, new CryptoRequestContext("request", key, new byte[]{1, 2, 3},
                new SessionKeyTransport("key:2", "wrapped-key")));
        assertNotEquals(context, null);
        assertNotEquals(context, "request");
        assertEquals(context.toString(), equalContext.toString());
        assertTrue(context.toString().contains("iv=[1, 2, 3]"));
    }

    @Test
    void handlesNullAndEmptyArrays() {
        var context = new CryptoRequestContext(null, null, null, null);
        var equalContext = new CryptoRequestContext(null, null, null, null);

        assertEquals(context, equalContext);
        assertEquals(context.hashCode(), equalContext.hashCode());
        assertTrue(context.toString().contains("iv=null"));
        assertNotEquals(context, new CryptoRequestContext(null, null, new byte[0], null));
    }
}
