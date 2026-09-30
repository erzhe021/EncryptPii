package com.ikea.crypto.server.error;

import com.ikea.crypto.stc.exception.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CryptoExceptionHierarchyTest {

    private final CryptoExceptionHandler handler = new CryptoExceptionHandler();

    @Test
    void testClientSideExceptionsAre4xx() {
        InvalidCryptoPayloadException payloadEx = new InvalidCryptoPayloadException("bad json");
        SessionKeyDecryptionException sessionKeyEx = new SessionKeyDecryptionException("key expired");
        DataTamperedException tamperedEx = new DataTamperedException("tag mismatch");

        assertTrue(payloadEx instanceof CryptoClientSideException);
        assertTrue(sessionKeyEx instanceof CryptoClientSideException);
        assertTrue(tamperedEx instanceof CryptoClientSideException);
        assertTrue(payloadEx instanceof CryptoException);

        ErrorResponse resp1 = handler.handleClientSideError(payloadEx);
        assertEquals("bad json", resp1.error());

        ErrorResponse resp2 = handler.handleClientSideError(sessionKeyEx);
        assertEquals("key expired", resp2.error());

        ErrorResponse resp3 = handler.handleClientSideError(tamperedEx);
        assertEquals("tag mismatch", resp3.error());
    }

    @Test
    void testServerSideExceptionsAre5xxAndSanitized() {
        KeyNotAvailableException keyNotAvailable = new KeyNotAvailableException("Vault unreachable");
        ResponseEncryptionException responseEncryptEx = new ResponseEncryptionException("AES init error");

        assertTrue(keyNotAvailable instanceof CryptoServerSideException);
        assertTrue(responseEncryptEx instanceof CryptoServerSideException);
        assertTrue(keyNotAvailable instanceof CryptoException);

        ErrorResponse resp1 = handler.handleServerSideError(keyNotAvailable);
        assertEquals("Cryptographic service internal error", resp1.error());

        ErrorResponse resp2 = handler.handleServerSideError(responseEncryptEx);
        assertEquals("Cryptographic service internal error", resp2.error());
    }
}
