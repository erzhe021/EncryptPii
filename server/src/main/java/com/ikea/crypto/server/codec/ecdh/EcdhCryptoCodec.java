package com.ikea.crypto.server.codec.ecdh;

import com.ikea.crypto.common.rsa.SessionKeyTransport;
import com.ikea.crypto.common.ecdh.EcdhCipherPayload;
import com.ikea.crypto.common.ecdh.EcdhHandshakeContext;
import com.ikea.crypto.server.codec.AbstractCryptoCodec;
import com.ikea.crypto.server.model.CryptoAlgorithm;
import com.ikea.crypto.server.context.CryptoSessionContext;
import com.ikea.crypto.server.error.InvalidCryptoPayloadException;
import com.ikea.crypto.server.service.EcdhCryptoServer;
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
                    "SessionKeyTransport is not supported for ECDH response encryption; use EcdhHandshakeContext or EcdhCipherPayload instead."
            );
        }
        if (sessionContext.requestKeyMaterial() instanceof EcdhHandshakeContext ecdhHandshakeContext) {
            return ecdhCryptoServer.encryptWithEcdhHandshakeContext(responseBodyString, ecdhHandshakeContext);
        }
        if (sessionContext.requestKeyMaterial() instanceof EcdhCipherPayload requestPayload) {
            EcdhHandshakeContext ecdhHandshakeContext = new EcdhHandshakeContext(
                    requestPayload.clientEphemeralPublicKeyBase64(),
                    requestPayload.serverEphemeralPublicKeyBase64()
            );
            return ecdhCryptoServer.encryptWithEcdhHandshakeContext(responseBodyString, ecdhHandshakeContext);
        }
        throw new InvalidCryptoPayloadException("Unsupported ECDH session key material: " + sessionContext.requestKeyMaterial());
    }
}
