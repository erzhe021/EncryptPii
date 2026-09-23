package com.example.demo.server.crypto.rsa;

import com.example.demo.crypto.CryptoConstants;
import com.example.demo.crypto.EncodingUtils;
import com.example.demo.crypto.rsa.RsaCipherPayload;
import com.example.demo.crypto.rsa.RsaPublicKeyResponse;

import java.security.GeneralSecurityException;

public class RsaCryptoService {
    private final RsaCryptoServer cryptoServer;

    public RsaCryptoService(RsaCryptoServer cryptoServer) {
        this.cryptoServer = cryptoServer;
    }

    public RsaPublicKeyResponse getPublicKey() {
        return new RsaPublicKeyResponse(
                CryptoConstants.ALGORITHM_RSA,
                EncodingUtils.toBase64(cryptoServer.rsaPublicKey().getEncoded())
        );
    }

    public String decrypt(RsaCipherPayload payload) throws GeneralSecurityException {
        return cryptoServer.decrypt(payload);
    }
}
