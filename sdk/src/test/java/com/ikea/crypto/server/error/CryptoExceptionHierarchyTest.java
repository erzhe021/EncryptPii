package com.ikea.crypto.server.error;

import com.ikea.crypto.stc.exception.*;
import com.ikea.crypto.stc.model.PublicKeyResponse;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CryptoExceptionHierarchyTest {

    @Test
    void testClientSideExceptionsPreserveTypesAndMessages() {
        InvalidCryptoPayloadException payloadEx = new InvalidCryptoPayloadException("bad json");
        SessionKeyDecryptionException sessionKeyEx = new SessionKeyDecryptionException("key expired");
        DataTamperedException tamperedEx = new DataTamperedException("tag mismatch");

        assertTrue(payloadEx instanceof CryptoClientSideException);
        assertTrue(sessionKeyEx instanceof CryptoClientSideException);
        assertTrue(tamperedEx instanceof CryptoClientSideException);
        assertTrue(payloadEx instanceof CryptoException);

        assertEquals("bad json", payloadEx.getMessage());
        assertEquals("key expired", sessionKeyEx.getMessage());
        assertEquals("tag mismatch", tamperedEx.getMessage());
    }

    @Test
    void testServerSideExceptionsPreserveDetailsForApplicationHandlers() {
        KeyNotAvailableException keyNotAvailable = new KeyNotAvailableException("Vault unreachable");
        ResponseEncryptionException responseEncryptEx = new ResponseEncryptionException("AES init error");

        assertTrue(keyNotAvailable instanceof CryptoServerSideException);
        assertTrue(responseEncryptEx instanceof CryptoServerSideException);
        assertTrue(keyNotAvailable instanceof CryptoException);

        assertEquals("Vault unreachable", keyNotAvailable.getMessage());
        assertEquals("AES init error", responseEncryptEx.getMessage());
    }

    @Test
    void testExpiredKeyExceptionContainsReplacementKey() {
        PublicKeyResponse latest = new PublicKeyResponse("public-key", "ciam:2", 123456789L);
        KeyExpiredException exception = new KeyExpiredException(latest);
        assertInstanceOf(CryptoClientSideException.class, exception);
        assertEquals(latest, exception.latestKey());
    }
}
