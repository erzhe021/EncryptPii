package com.example.demo.server.crypto;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.RsaHybridCipherPayload;
import com.example.demo.crypto.RsaHybridCryptoServer;
import com.example.demo.crypto.RsaPublicKeyResponse;

import java.security.GeneralSecurityException;

public class RsaCryptoService {
    private final RsaHybridCryptoServer cryptoServer;

    public RsaCryptoService(RsaHybridCryptoServer cryptoServer) {
        this.cryptoServer = cryptoServer;
    }

    public RsaPublicKeyResponse getPublicKey() {
        return new RsaPublicKeyResponse(
                CryptoConstants.ALGORITHM_RSA,
                EncodingUtils.toBase64(cryptoServer.rsaPublicKey().getEncoded())
        );
    }

    public String decrypt(RsaHybridCipherPayload payload) throws GeneralSecurityException {
        return cryptoServer.decrypt(payload);
    }
}
