package com.example.demo.server.crypto.rsa;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.DefaultAesCipherPayload;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.SessionKeyTransport;
import com.example.demo.crypto.core.AesGcmCryptoService;
import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.server.crypto.AbstractCryptoCodec;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.CryptoSessionContext;
import com.example.demo.server.crypto.InvalidCryptoPayloadException;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public class RsaCryptoCodec extends AbstractCryptoCodec {
    private final RsaCryptoServer rsaCryptoServer;

    public RsaCryptoCodec(RsaCryptoServer rsaCryptoServer, ObjectMapper objectMapper) {
        super(objectMapper);
        this.rsaCryptoServer = rsaCryptoServer;
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return CryptoAlgorithm.RSA;
    }

    @Override
    protected String doDecrypt(CryptoSessionContext<?> sessionContext) throws GeneralSecurityException {
        if (sessionContext.requestKeyMaterial() instanceof RsaCipherPayload payload) {
            return rsaCryptoServer.decrypt(payload);
        }
        throw new InvalidCryptoPayloadException("Unsupported RSA session key material: " + sessionContext.requestKeyMaterial());
    }

    @Override
    protected Object doEncrypt(String responseBodyString, CryptoSessionContext<?> sessionContext) throws GeneralSecurityException {
        if (sessionContext.requestKeyMaterial() instanceof SessionKeyTransport sessionKeyTransport) {
            return encryptWithSessionKeyTransport(responseBodyString, sessionKeyTransport);
        }
        if (sessionContext.requestKeyMaterial() instanceof RsaCipherPayload requestPayload) {
            rsaCryptoServer.validatePayload(requestPayload);
            return rsaCryptoServer.encryptWithRequestSessionKey(responseBodyString, requestPayload.encryptedSessionKeyBase64());
        }
        throw new InvalidCryptoPayloadException("Unsupported RSA session key material: " + sessionContext.requestKeyMaterial());
    }

    private DefaultAesCipherPayload encryptWithSessionKeyTransport(String responseBodyString, SessionKeyTransport sessionKeyTransport)
            throws GeneralSecurityException {
        SecretKey sessionKey = new SecretKeySpec(
                rsaCryptoServer.decryptSessionKey(sessionKeyTransport.encryptedSessionKeyBase64()),
                CryptoConstants.ALGORITHM_AES
        );
        byte[] iv = EncodingUtils.fromBase64(sessionKeyTransport.ivBase64());
        String encryptedDataBase64 = AesGcmCryptoService.encryptAsBase64(responseBodyString, sessionKey, iv);
        return new DefaultAesCipherPayload(
                sessionKeyTransport.ivBase64(),
                encryptedDataBase64
        );
    }
}
