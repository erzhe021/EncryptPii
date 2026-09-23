package com.example.demo.server.crypto.ecdh;

import com.example.demo.crypto.ecdh.EcdhCipherPayload;
import com.example.demo.crypto.ecdh.EcdhPublicKeyResponse;

import java.security.GeneralSecurityException;

public class EcdhCryptoService {
    private final EcdhCryptoServer cryptoServer;

    public EcdhCryptoService(EcdhCryptoServer cryptoServer) {
        this.cryptoServer = cryptoServer;
    }

    public EcdhPublicKeyResponse getPublicKey() throws GeneralSecurityException {
        return cryptoServer.generateEphemeralEcdhPublicKey();
    }

    public String decrypt(EcdhCipherPayload payload) throws GeneralSecurityException {
        return cryptoServer.decrypt(payload);
    }
}
