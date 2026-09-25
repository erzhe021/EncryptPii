package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.SessionKeyTransport;
import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhContext;
import com.example.demo.server.crypto.AbstractCryptoCodec;
import com.example.demo.server.crypto.CryptoAlgorithm;
import com.example.demo.server.crypto.CryptoSessionContext;
import com.example.demo.server.crypto.InvalidCryptoPayloadException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.security.GeneralSecurityException;

public class EcdhCryptoCodec extends AbstractCryptoCodec {
    private final EcdhCryptoServer ecdhCryptoServer;

    public EcdhCryptoCodec(EcdhCryptoServer ecdhCryptoServer, ObjectMapper objectMapper) {
        super(objectMapper);
        this.ecdhCryptoServer = ecdhCryptoServer;
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return CryptoAlgorithm.ECDH;
    }

    @Override
    protected String doDecrypt(CryptoSessionContext<?> sessionContext) throws GeneralSecurityException {
        if (sessionContext.requestKeyMaterial() instanceof EcdhCipherPayload payload) {
            return ecdhCryptoServer.decrypt(payload);
        }
        throw new InvalidCryptoPayloadException("Unsupported ECDH session key material: " + sessionContext.requestKeyMaterial());
    }

    @Override
    protected Object doEncrypt(String responseBodyString, CryptoSessionContext<?> sessionContext) throws GeneralSecurityException {
        if (sessionContext.requestKeyMaterial() instanceof SessionKeyTransport) {
            throw new InvalidCryptoPayloadException(
                    "SessionKeyTransport is not supported for ECDH response encryption; use EcdhContext or EcdhCipherPayload instead."
            );
        }
        if (sessionContext.requestKeyMaterial() instanceof EcdhContext ecdhContext) {
            return ecdhCryptoServer.encryptWithEcdhContext(responseBodyString, ecdhContext);
        }
        if (sessionContext.requestKeyMaterial() instanceof EcdhCipherPayload requestPayload) {
            EcdhContext ecdhContext = new EcdhContext(
                    requestPayload.clientEphemeralPublicKeyBase64(),
                    requestPayload.serverEphemeralPublicKeyBase64()
            );
            return ecdhCryptoServer.encryptWithEcdhContext(responseBodyString, ecdhContext);
        }
        throw new InvalidCryptoPayloadException("Unsupported ECDH session key material: " + sessionContext.requestKeyMaterial());
    }
}
