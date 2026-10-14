package com.ikea.crypto.stc.key;

import com.ikea.crypto.stc.crypto.AesGcmCipher;
import com.ikea.crypto.stc.crypto.SessionKeyService;
import com.ikea.crypto.stc.exception.CryptoServerSideException;
import com.ikea.crypto.stc.exception.DataTamperedException;
import com.ikea.crypto.stc.exception.InvalidCryptoRequestException;
import com.ikea.crypto.stc.exception.SessionKeyDecryptionException;
import com.ikea.crypto.stc.model.CipherRequestPayload;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CryptoServerExceptionClassificationTest {

    private final CryptoServer server = new CryptoServer(
            new KeyRing("test", 120000, 10000, false, 20000));
    private final SecretKeySpec aesKey = new SecretKeySpec(new byte[16], "AES");

    @Test
    void invalidBase64IsAClientError() {
        InvalidCryptoRequestException exception = assertThrows(InvalidCryptoRequestException.class,
                () -> server.decrypt(new CipherRequestPayload("!", base64(new byte[16])), aesKey));
        assertEquals("Invalid Base64 format in encrypted data or IV.", exception.getMessage());
    }

    @Test
    void invalidIvAndTruncatedTagAreExplicitClientErrors() {
        InvalidCryptoRequestException ivError = assertThrows(InvalidCryptoRequestException.class,
                () -> server.decrypt(new CipherRequestPayload(base64(new byte[1]), base64(new byte[16])), aesKey));
        assertEquals("IV must contain exactly 12 bytes.", ivError.getMessage());
        InvalidCryptoRequestException tagError = assertThrows(InvalidCryptoRequestException.class,
                () -> server.decrypt(new CipherRequestPayload(base64(new byte[12]), base64(new byte[15])), aesKey));
        assertEquals("Encrypted data must include a 16-byte GCM authentication tag.", tagError.getMessage());
    }

    @Test
    void authenticationFailureRemainsATamperingError() throws Exception {
        byte[] iv = new byte[12];
        byte[] encrypted = AesGcmCipher.encrypt("message".getBytes(java.nio.charset.StandardCharsets.UTF_8), aesKey, iv);
        encrypted[0] ^= 1;
        assertThrows(DataTamperedException.class,
                () -> server.decrypt(new CipherRequestPayload(base64(iv), base64(encrypted)), aesKey));
    }

    @Test
    void invalidServerSideAesKeyIsNotReportedAsBadBase64() {
        assertThrows(CryptoServerSideException.class, () -> server.decrypt(
                new CipherRequestPayload(base64(new byte[12]), base64(new byte[16])),
                new SecretKeySpec(new byte[8], "AES")));
    }

    @Test
    void rsaInitializationFailureDoesNotTryOtherKeys() throws Exception {
        server.keyRing().initialize();
        var entry = server.keyRing().getActiveKeyEntry();
        NoSuchAlgorithmException cause = new NoSuchAlgorithmException("RSA unavailable");
        try (var service = mockStatic(SessionKeyService.class)) {
            service.when(() -> SessionKeyService.decryptSessionKeyBase64("wrapped", entry.privateKey()))
                    .thenThrow(cause);
            CryptoServerSideException exception = assertThrows(CryptoServerSideException.class,
                    () -> server.decryptSessionKeyToSecretKey(entry.metadata().keyId(), "wrapped"));
            assertSame(cause, exception.getCause());
            service.verify(() -> SessionKeyService.decryptSessionKeyBase64("wrapped", entry.privateKey()), times(1));
        }
    }

    @Test
    void invalidRsaCiphertextRemainsAClientError() throws Exception {
        server.keyRing().initialize();
        assertThrows(SessionKeyDecryptionException.class, () -> server.decryptSessionKeyToSecretKey(
                server.getPublicKey().keyId(), base64(new byte[256])));
    }

    private String base64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
