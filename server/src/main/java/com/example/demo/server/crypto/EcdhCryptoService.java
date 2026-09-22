package com.example.demo.server.crypto;

import com.example.demo.crypto.EcdhHybridCipherPayload;
import com.example.demo.crypto.EcdhHybridCryptoServer;
import com.example.demo.crypto.EcdhPublicKeyResponse;

import java.security.GeneralSecurityException;

public class EcdhCryptoService {
    private final EcdhHybridCryptoServer cryptoServer;

    public EcdhCryptoService(EcdhHybridCryptoServer cryptoServer) {
        this.cryptoServer = cryptoServer;
    }

    public EcdhPublicKeyResponse getPublicKey() throws GeneralSecurityException {
        return cryptoServer.generateEphemeralEcdhPublicKey();
    }

    public String decrypt(EcdhHybridCipherPayload payload) throws GeneralSecurityException {
        return cryptoServer.decrypt(payload);
    }
}
